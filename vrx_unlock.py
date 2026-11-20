"""Unlock a Caddx / Walksnail Ascent VRX Pro or VRX Max over the RNDIS
USB-LAN link.

The device speaks the documented "Ascent VRX Max" binary frame protocol over
UDP (Ctrl channel, default port 9001).  This script:

  * checks the Windows RNDIS adapter and repairs its IPv4 settings if asked;
  * discovers the VRX on the USB subnet;
  * sends the Debug3 Mode key (key_num 9, press_type 0) to unlock the unit;
  * prints any replies the device sends back.

Frame layout (multi-byte fields are big-endian):

    FE EF | CMD (1) | LEN (2) | PAYLOAD (0..65535) | SUM (2) | 0D 0A

CMD 0x22 = write (host -> device), 0xA2 = read request/response.
SUM is the 16-bit sum of the payload bytes only.

This project is standalone: only the standard library is required.  The RNDIS
check/fix helpers live in `vrx_unlock_network.py` next to this file.

Usage
-----
    python vrx_unlock.py                      # check network + send Debug3
    python vrx_unlock.py unlock --repeat 5
    python vrx_unlock.py net-check            # inspect the RNDIS settings only
    python vrx_unlock.py net-fix              # set 192.168.3.103/24 (UAC)
    python vrx_unlock.py restore-network      # undo a previous net-fix
    python vrx_unlock.py discover             # find the device, send no keys
    python vrx_unlock.py key confirm          # send any documented key
    python vrx_unlock.py status               # read wireless status
    python vrx_unlock.py --host 192.168.3.102 unlock
    python vrx_unlock.py --dry-run            # show the frame, send nothing

Key simulation is fire-and-forget, so confirm the result on the VRX HDMI/OSD
output.  Nothing here writes to the device.

Protocol reference: https://github.com/CaddxFPV-Tech/Caddx_vrx_max_udp_protocol
"""

from __future__ import annotations

import argparse
import select
import socket
import sys
import time
from dataclasses import dataclass

import vrx_unlock_network as net

HEADER = bytes.fromhex("FE EF")
TAIL = bytes.fromhex("0D 0A")
WRITE_COMMAND = 0x22
READ_COMMAND = 0xA2
MAX_PAYLOAD_LENGTH = 0xFFFF

DEFAULT_CTRL_PORT = 9001
DEFAULT_OSD_PORT = 9200

# Documented endpoints: USB-C/RNDIS is 192.168.3.102, RJ45 is 192.168.1.100.
KNOWN_DEVICE_IPS = ("192.168.3.102", "192.168.1.100")
USB_VRX_IP = KNOWN_DEVICE_IPS[0]
USB_HOST_SUBNET = "192.168.3."

# key name -> (key_num, press_type); cmd_type for all of these is 0x40.
KEYS: dict[str, tuple[int, int]] = {
    "up": (0, 0),
    "down": (1, 0),
    "left": (2, 0),
    "right": (3, 0),
    "confirm": (4, 0),
    "pairing": (5, 0),
    "upgrade": (5, 1),
    "recording": (6, 0),
    "back": (7, 0),
    "force-720p60": (7, 1),
    "debug3": (9, 0),
}

UNLOCK_KEY = "debug3"
BANDS = {0: "A", 1: "B", 2: "C"}


class ProtocolError(ValueError):
    """Raised when a datagram violates the VRX frame format."""


# --------------------------------------------------------------------------
# Frame assembly / parsing
# --------------------------------------------------------------------------


def calculate_checksum(payload: bytes) -> bytes:
    """Return the 16-bit payload sum as two big-endian bytes."""
    return (sum(payload) & 0xFFFF).to_bytes(2, byteorder="big")


def assemble_packet(command: int, payload: bytes) -> bytes:
    """Wrap `payload` in a complete VRX frame.

    Args:
        command: One-byte protocol command (0x22 write, 0xA2 read, ...).
        payload: Command-specific payload bytes.

    Returns:
        Header + command + length + payload + checksum + tail.

    Raises:
        ValueError: If the command or payload length is out of range.
    """
    if not 0 <= command <= 0xFF:
        raise ValueError("command must be an unsigned byte")
    if len(payload) > MAX_PAYLOAD_LENGTH:
        raise ValueError("payload exceeds 65535 bytes")

    return (
        HEADER
        + bytes([command])
        + len(payload).to_bytes(2, byteorder="big")
        + payload
        + calculate_checksum(payload)
        + TAIL
    )


def build_key_packet(key_name: str) -> bytes:
    """Build a key-simulation frame for a documented key name."""
    try:
        key_number, press_type = KEYS[key_name]
    except KeyError:
        raise ValueError(
            f"unknown key {key_name!r}; choose from: {', '.join(sorted(KEYS))}"
        ) from None

    payload = bytes([0x40, key_number, press_type, 0x00])
    return assemble_packet(WRITE_COMMAND, payload)


def build_read_packet(command_type: int) -> bytes:
    """Build an 8-byte read request (0x51/0x52/0x53)."""
    return assemble_packet(READ_COMMAND, bytes([command_type]) + bytes(7))


def parse_packet(data: bytes) -> tuple[int, bytes]:
    """Validate one complete frame and return (command, payload).

    Raises:
        ProtocolError: On a bad header, length, checksum, or tail.
    """
    minimum_size = 2 + 1 + 2 + 2 + 2
    if len(data) < minimum_size:
        raise ProtocolError("packet is shorter than the minimum frame length")
    if data[:2] != HEADER:
        raise ProtocolError("invalid header")

    payload_length = int.from_bytes(data[3:5], byteorder="big")
    expected_size = 2 + 1 + 2 + payload_length + 2 + 2
    if len(data) != expected_size:
        raise ProtocolError(
            f"length mismatch: declared {payload_length} payload bytes, "
            f"received {len(data)} total bytes"
        )

    payload_end = 5 + payload_length
    payload = data[5:payload_end]
    if data[payload_end:payload_end + 2] != calculate_checksum(payload):
        raise ProtocolError("checksum mismatch")
    if data[payload_end + 2:payload_end + 4] != TAIL:
        raise ProtocolError("invalid tail")

    return data[2], payload


def decode_payload(payload: bytes) -> dict[str, object]:
    """Decode a known read-response payload into named values."""
    if not payload:
        return {"type": "empty"}

    command_type = payload[0]
    values = payload[1:]

    if command_type == 0x51 and len(values) >= 3:
        return {
            "type": "frequency",
            "band": BANDS.get(values[0], f"unknown({values[0]})"),
            "channel": values[1],
            "hopping": values[2] == 1,
        }
    if command_type == 0x52 and len(values) >= 6:
        return {
            "type": "wireless_status",
            "rssi1": values[0],
            "rssi2": values[1],
            "data_rate_mbps": values[3],
            "delay_ms": values[4],
            "connected": values[5] == 1,
        }
    if command_type == 0x53 and len(values) >= 5:
        settable: list[int] = []
        for byte_index, bitmap_byte in enumerate(values[1:5]):
            for bit_index in range(8):
                if bitmap_byte & (1 << bit_index):
                    settable.append(byte_index * 8 + bit_index)
        return {
            "type": "power",
            "power_index": values[0],
            "settable_indices": settable,
        }
    return {"type": "unknown", "command_type": command_type, "data": bytes(values)}


# --------------------------------------------------------------------------
# RNDIS network check / repair
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class NetworkTarget:
    """Local address to send from, plus a label for the adapter."""

    host_ip: str
    adapter_name: str = ""


def _status_mark(status: str | None) -> str:
    return {"ok": "OK  ", "bad": "FAIL", None: "--  "}.get(status, "--  ")


def describe_network(reachable: bool = False) -> bool:
    """Print the RNDIS state rows; return True when the subnet is usable."""
    state = net.analyze()
    print("RNDIS / USB network:")
    for label, value, status in net.describe_state(state):
        print(f"  [{_status_mark(status)}] {label}: {value}")

    if not state.configured:
        if state.adapter is not None and state.proposed_host_ip is not None:
            print("\nProposed fix:")
            print(
                "  "
                + net.manual_static_ip_command(
                    state.adapter, state.proposed_host_ip, state.proposed_prefix
                )
            )
            print("  or run: python vrx_unlock.py net-fix")
        return False

    adapter = state.adapter
    print(f"  -> sending from {state.host_ip} on {adapter.name if adapter else '?'}")
    if reachable:
        result = net.check_reachability()
        if result.present:
            print(f"  [OK  ] VRX reachable: {result.detail}")
        else:
            print(
                "  [--  ] VRX not reachable yet: "
                f"{result.detail} (the UDP unlock may still work)"
            )
    return True


def fix_network() -> bool:
    """Apply the proposed static address to the RNDIS adapter (UAC)."""
    state = net.analyze()
    if state.configured:
        print("RNDIS settings are already usable; nothing to change.")
        return True
    if state.adapter is None:
        print("No RNDIS/USB adapter found. Connect the VRX with a USB data cable.")
        return False
    if state.proposed_host_ip is None:
        print("Could not find a free host address in 192.168.3.0/24.")
        return False

    try:
        saved = net.save_network_state(state.adapter)
        print(f"Saved current settings to: {saved}")
    except net.NetworkError as error:
        print(f"Note: could not save the current settings ({error}).")

    print(
        f"Setting {state.proposed_host_ip}/{state.proposed_prefix} on "
        f"{state.adapter.label} (approve the UAC prompt)..."
    )
    ok, message = net.apply_static_ip(
        state.adapter, state.proposed_host_ip, state.proposed_prefix
    )
    if message:
        print(f"  {message}")
    if not ok:
        print("Static IP could not be applied. Run the printed netsh command manually.")
        return False

    time.sleep(1.5)
    state = net.analyze()
    if state.configured:
        print(f"RNDIS ready: host {state.host_ip}, VRX {net.VRX_IP}.")
        print("Undo later with: python vrx_unlock.py restore-network")
        return True

    print("Adapter still has no usable address after the change.")
    return False


def ensure_network(args: argparse.Namespace) -> NetworkTarget | None:
    """Check the RNDIS adapter, optionally fixing it, and return the local IP."""
    if args.no_network_check:
        return NetworkTarget(args.local_ip) if args.local_ip else None

    if not net.is_windows():
        print("RNDIS check skipped: automatic checks are Windows-only.")
        return NetworkTarget(args.local_ip) if args.local_ip else None

    usable = describe_network()
    if not usable and args.fix_network:
        print()
        usable = fix_network()

    if not usable:
        return None

    state = net.analyze()
    if state.host_ip is None:
        return NetworkTarget(args.local_ip) if args.local_ip else None
    adapter_name = state.adapter.name if state.adapter else ""
    return NetworkTarget(str(state.host_ip), adapter_name)


def _fallback_local_ips() -> list[str]:
    """Best-effort local IPv4 list when adapter inspection is unavailable."""
    addresses: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addresses.add(info[4][0])
    except OSError:
        pass
    for probe in (USB_VRX_IP, "8.8.8.8"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((probe, 9))
                addresses.add(sock.getsockname()[0])
        except OSError:
            pass
    return sorted(ip for ip in addresses if not ip.startswith("127."))


# --------------------------------------------------------------------------
# UDP link and discovery
# --------------------------------------------------------------------------


@dataclass
class Hit:
    """A responding VRX endpoint."""

    host: str
    port: int
    local_address: str
    reply: dict[str, object]
    raw: bytes


class UdpLink:
    """UDP socket bound to one local interface and aimed at the VRX."""

    def __init__(self, host: str, port: int, local_address: str | None = None):
        self.address = (host, port)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((local_address or "", 0))
        self.socket.connect(self.address)
        self.socket.setblocking(False)

    def send(self, packet: bytes) -> None:
        self.socket.send(packet)

    def drain(self, timeout: float) -> list[tuple[bytes, tuple[str, int]]]:
        """Collect datagrams arriving within `timeout` seconds."""
        received: list[tuple[bytes, tuple[str, int]]] = []
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                readable, _, _ = select.select([self.socket], [], [], remaining)
            except OSError:
                break
            if not readable:
                break
            try:
                data, source = self.socket.recvfrom(MAX_PAYLOAD_LENGTH + 9)
            except ConnectionResetError:
                # Windows surfaces an ICMP "port unreachable" this way.
                break
            except OSError:
                break
            received.append((data, source))
        return received

    def close(self) -> None:
        self.socket.close()

    def __enter__(self) -> "UdpLink":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def candidate_hosts(local_address: str) -> list[str]:
    """Addresses worth probing from `local_address`, most likely first."""
    if local_address.startswith(USB_HOST_SUBNET):
        return [USB_VRX_IP, *_same_24_octets(local_address)]
    return [*_same_24_octets(local_address), *KNOWN_DEVICE_IPS]


def _same_24_octets(local_address: str) -> list[str]:
    base = local_address.rsplit(".", 1)[0]
    octets = (102, 103, 100, 101, 1, 2)
    return [f"{base}.{octet}" for octet in octets]


def probe_endpoints(
    local_addresses: list[str],
    ports: list[int],
    timeout: float = 1.5,
    verbose: bool = False,
) -> list[Hit]:
    """Send one status read to each candidate and collect valid replies."""
    probe = build_read_packet(0x52)
    pending: list[tuple[socket.socket, str, int, str]] = []
    seen: set[tuple[str, str, int]] = set()

    for local_address in local_addresses:
        for host in dict.fromkeys(candidate_hosts(local_address)):
            for port in ports:
                if host == local_address:
                    continue
                if (local_address, host, port) in seen:
                    continue
                seen.add((local_address, host, port))
                link_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    link_socket.bind((local_address, 0))
                    link_socket.connect((host, port))
                    link_socket.setblocking(False)
                    if verbose:
                        print(f"  probe {local_address} -> {host}:{port}")
                    link_socket.send(probe)
                except OSError:
                    link_socket.close()
                    continue
                pending.append((link_socket, host, port, local_address))

    hits: list[Hit] = []
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        readable, _, _ = select.select([entry[0] for entry in pending], [], [], 0.05)
        for ready in readable:
            entry = next(item for item in pending if item[0] is ready)
            link_socket, host, port, local_address = entry
            try:
                data, _source = link_socket.recvfrom(MAX_PAYLOAD_LENGTH + 9)
            except OSError:
                pending.remove(entry)
                link_socket.close()
                continue
            try:
                _command, payload = parse_packet(data)
            except ProtocolError:
                continue
            hits.append(Hit(host, port, local_address, decode_payload(payload), data))
            pending.remove(entry)
            link_socket.close()

    for link_socket, _host, _port, _local in pending:
        link_socket.close()

    return hits


# --------------------------------------------------------------------------
# Output helpers
# --------------------------------------------------------------------------


def hex_bytes(data: bytes) -> str:
    return data.hex(" ").upper()


def print_replies(replies: list[tuple[bytes, tuple[str, int]]]) -> int:
    """Print and decode received datagrams; return how many were valid."""
    valid = 0
    for data, source in replies:
        print(f"  RX <- {source[0]}:{source[1]}  {hex_bytes(data)}")
        try:
            command, payload = parse_packet(data)
        except ProtocolError as error:
            print(f"    invalid frame: {error}")
            continue
        valid += 1
        print(f"    command: 0x{command:02X}")
        for key, value in decode_payload(payload).items():
            print(f"    {key}: {value}")
    return valid


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def resolve_target(args: argparse.Namespace):
    """Return (host, port, local_address, description) or None."""
    if args.host:
        return args.host, args.port, args.local_ip, "explicit --host"

    target = ensure_network(args)
    if args.local_ip:
        local_addresses = [args.local_ip]
    elif target is not None and target.host_ip:
        local_addresses = [target.host_ip]
    else:
        local_addresses = _fallback_local_ips()

    if not local_addresses:
        return None

    probe_ports = sorted({args.port, *args.ports})
    hits = probe_endpoints(
        local_addresses, probe_ports, timeout=args.timeout, verbose=args.verbose
    )
    if hits:
        best = hits[0]
        return (
            best.host,
            best.port,
            best.local_address,
            f"discovered from {best.local_address}",
        )

    usb_locals = [ip for ip in local_addresses if ip.startswith(USB_HOST_SUBNET)]
    if usb_locals:
        print(
            f"\nNo reply to the discovery probe. Trying {USB_VRX_IP}:{args.port} "
            f"from {usb_locals[0]} anyway (key simulation may still work)."
        )
        return USB_VRX_IP, args.port, usb_locals[0], "fallback"

    return None


def send_and_listen(args: argparse.Namespace, packet: bytes, label: str) -> int:
    if args.dry_run:
        target_label = args.host or "auto-detect at run time"
        print(f"\nTarget: {target_label}:{args.port}")
        print(f"TX {label}: {hex_bytes(packet)}")
        print("Dry run: nothing sent.")
        return 0

    target = resolve_target(args)
    if target is None:
        print(
            "\nCould not determine how to reach the VRX. Connect the USB-C data "
            "cable, or pass --host / --local-ip explicitly."
        )
        return 1

    host, port, local_address, how = target
    print(f"\nTarget: {host}:{port} ({how})")
    print(f"TX {label}: {hex_bytes(packet)}")

    try:
        with UdpLink(host, port, local_address) as link:
            for index in range(args.repeat):
                link.send(packet)
                if index + 1 < args.repeat:
                    time.sleep(args.interval)
            print(f"Sent {args.repeat} frame(s), {args.interval:.2f}s apart.")
            replies = link.drain(args.listen)
    except OSError as error:
        print(f"UDP error: {error}", file=sys.stderr)
        return 1

    valid = print_replies(replies)
    if not replies:
        print("  no reply (expected for key simulation).")
    elif not valid:
        print("  replies were not valid VRX frames.")

    if label.startswith("Debug3"):
        print(
            "\nDebug3 key sent. Check the VRX HDMI/OSD output to confirm the "
            "unlock actually took effect."
        )
    return 0


def cmd_unlock(args: argparse.Namespace) -> int:
    return send_and_listen(args, build_key_packet(UNLOCK_KEY), "Debug3 key")


def cmd_key(args: argparse.Namespace) -> int:
    try:
        packet = build_key_packet(args.key_name)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return send_and_listen(args, packet, f"key {args.key_name}")


def cmd_status(args: argparse.Namespace) -> int:
    return send_and_listen(args, build_read_packet(0x52), "wireless status read")


def cmd_raw(args: argparse.Namespace) -> int:
    """Send a write frame with an arbitrary hex payload (investigation tool)."""
    text = args.payload.replace(" ", "").replace("_", "").replace("-", "")
    try:
        payload = bytes.fromhex(text)
    except ValueError:
        print(f"error: {args.payload!r} is not valid hex", file=sys.stderr)
        return 2
    if not payload:
        print("error: payload is empty", file=sys.stderr)
        return 2
    return send_and_listen(
        args, assemble_packet(WRITE_COMMAND, payload), f"raw payload {payload.hex(' ').upper()}"
    )


def cmd_get_frequency(args: argparse.Namespace) -> int:
    return send_and_listen(args, build_read_packet(0x51), "frequency read")


def cmd_get_power(args: argparse.Namespace) -> int:
    return send_and_listen(args, build_read_packet(0x53), "power read")


def cmd_discover(args: argparse.Namespace) -> int:
    target = ensure_network(args)
    if args.local_ip:
        local_addresses = [args.local_ip]
    elif target is not None and target.host_ip:
        local_addresses = [target.host_ip]
    else:
        local_addresses = _fallback_local_ips()
    if not local_addresses:
        print("No usable local IPv4 address.", file=sys.stderr)
        return 1

    print("\nProbing for the VRX...")
    hits = probe_endpoints(
        local_addresses,
        sorted({args.port, *args.ports}),
        timeout=args.timeout,
        verbose=args.verbose,
    )
    if not hits:
        print("No VRX answered. Check power, the USB data cable, and the IP fix.")
        return 1

    print("\nFound:")
    for hit in hits:
        print(f"  {hit.host}:{hit.port} (via {hit.local_address})  {hex_bytes(hit.raw)}")
        for key, value in hit.reply.items():
            print(f"    {key}: {value}")
    return 0


def cmd_net_check(args: argparse.Namespace) -> int:
    if not net.is_windows():
        print("RNDIS checks are Windows-only.", file=sys.stderr)
        return 1
    return 0 if describe_network(reachable=True) else 1


def cmd_net_fix(args: argparse.Namespace) -> int:
    if not net.is_windows():
        print("RNDIS checks are Windows-only.", file=sys.stderr)
        return 1
    describe_network()
    return 0 if fix_network() else 1


def cmd_restore_network(args: argparse.Namespace) -> int:
    if not net.is_windows():
        print("RNDIS checks are Windows-only.", file=sys.stderr)
        return 1
    saved = net.load_network_state()
    if saved is None:
        print(f"No saved settings at {net.STATE_PATH}.")
        return 1

    print(f"Saved: {net.describe_saved_state(saved)}")
    print("Restoring (approve the UAC prompt)...")
    ok, message = net.restore_network_state(saved)
    if message:
        print(f"  {message}")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def port_list(value: str) -> list[int]:
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
        except ValueError:
            raise argparse.ArgumentTypeError("ports must be integers") from None
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError("ports must be 1..65535")
        ports.append(port)
    if not ports:
        raise argparse.ArgumentTypeError("at least one port is required")
    return ports


def _global_options_after_command() -> argparse.ArgumentParser:
    """Options accepted after the subcommand without overriding earlier values."""
    common = argparse.ArgumentParser(add_help=False)
    suppress = argparse.SUPPRESS
    common.add_argument("--host", default=suppress, help=argparse.SUPPRESS)
    common.add_argument("--port", type=int, default=suppress, help=argparse.SUPPRESS)
    common.add_argument("--ports", type=port_list, default=suppress, help=argparse.SUPPRESS)
    common.add_argument("--local-ip", default=suppress, help=argparse.SUPPRESS)
    common.add_argument("--repeat", type=int, default=suppress, help=argparse.SUPPRESS)
    common.add_argument("--interval", type=float, default=suppress, help=argparse.SUPPRESS)
    common.add_argument("--listen", type=float, default=suppress, help=argparse.SUPPRESS)
    common.add_argument("--timeout", type=float, default=suppress, help=argparse.SUPPRESS)
    common.add_argument(
        "--fix-network", action="store_true", default=suppress, help=argparse.SUPPRESS
    )
    common.add_argument(
        "--no-network-check", action="store_true", default=suppress, help=argparse.SUPPRESS
    )
    common.add_argument("--dry-run", action="store_true", default=suppress, help=argparse.SUPPRESS)
    common.add_argument("--verbose", action="store_true", default=suppress, help=argparse.SUPPRESS)
    return common


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Send Debug3 keys and read status from a Caddx VRX Pro or VRX Max "
            "over RNDIS USB-LAN (UDP)."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", help="device IPv4; skips discovery")
    parser.add_argument("--port", type=int, default=DEFAULT_CTRL_PORT, help="Ctrl UDP port")
    parser.add_argument(
        "--ports",
        type=port_list,
        default=[DEFAULT_CTRL_PORT, DEFAULT_OSD_PORT, 9000],
        help="ports probed during discovery",
    )
    parser.add_argument("--local-ip", help="force the local interface address")
    parser.add_argument("--repeat", type=int, default=3, help="frames to send")
    parser.add_argument("--interval", type=float, default=0.25, help="seconds between frames")
    parser.add_argument("--listen", type=float, default=2.0, help="seconds to wait for replies")
    parser.add_argument("--timeout", type=float, default=1.5, help="discovery timeout (s)")
    parser.add_argument(
        "--fix-network",
        action="store_true",
        help="apply the static IP fix when the RNDIS adapter is wrong",
    )
    parser.add_argument(
        "--no-network-check", action="store_true", help="skip the RNDIS checks"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="show the frame without sending it"
    )
    parser.add_argument("--verbose", action="store_true", help="log probe attempts")

    common = _global_options_after_command()
    subcommands = parser.add_subparsers(dest="command")
    subcommands.add_parser(
        "unlock", parents=[common], help="send the Debug3 key (default)"
    )
    key_parser = subcommands.add_parser(
        "key", parents=[common], help="send a documented key"
    )
    key_parser.add_argument("key_name", choices=sorted(KEYS))
    subcommands.add_parser(
        "discover", parents=[common], help="find the device without sending keys"
    )
    subcommands.add_parser("status", parents=[common], help="read wireless status")
    raw_parser = subcommands.add_parser(
        "raw", parents=[common], help="send a write frame with a hex payload"
    )
    raw_parser.add_argument("payload", help="payload bytes as hex, e.g. 40090100")
    subcommands.add_parser(
        "get-frequency", parents=[common], help="read band/channel/hopping"
    )
    subcommands.add_parser("get-power", parents=[common], help="read power index")
    subcommands.add_parser(
        "net-check", parents=[common], help="inspect the RNDIS IPv4 settings"
    )
    subcommands.add_parser(
        "net-fix", parents=[common], help="set a static 192.168.3.x address (UAC)"
    )
    subcommands.add_parser(
        "restore-network", parents=[common], help="undo a previous net-fix (UAC)"
    )
    return parser


HANDLERS = {
    None: cmd_unlock,
    "unlock": cmd_unlock,
    "key": cmd_key,
    "raw": cmd_raw,
    "discover": cmd_discover,
    "status": cmd_status,
    "get-frequency": cmd_get_frequency,
    "get-power": cmd_get_power,
    "net-check": cmd_net_check,
    "net-fix": cmd_net_fix,
    "restore-network": cmd_restore_network,
}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if args.interval < 0:
        parser.error("--interval must not be negative")

    handler = HANDLERS[args.command]
    try:
        return handler(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
