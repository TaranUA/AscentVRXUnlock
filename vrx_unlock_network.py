"""Windows RNDIS/USB-Ethernet checks and fixes for the Caddx VRX.

The VRX exposes a USB composite gadget: a CDC-ACM serial port and an RNDIS
network interface fixed at ``192.168.3.102/24``.  The host needs an address in
the same subnet (``192.168.3.103`` by convention).  The device runs no DHCP
server, so without a static address Windows falls back to APIPA
(``169.254.x.x``) and never reaches the VRX.

This module is self-contained and uses only the Python standard library plus
PowerShell (Windows).  The approach is adapted from the AscentVRXRootTool
project; see README.md for attribution.
"""

from __future__ import annotations

import base64
import ctypes
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

VRX_IP = ipaddress.IPv4Address("192.168.3.102")
USB_SUBNET = ipaddress.IPv4Network("192.168.3.0/24")
PREFERRED_HOST_IP = ipaddress.IPv4Address("192.168.3.103")
USB_PREFIX = 24

STATE_PATH = (
    Path(os.environ.get("LOCALAPPDATA", str(Path.home())))
    / "AscentVRXUnlock"
    / "network_state.json"
)

RNDIS_KEYWORDS = (
    "rndis",
    "remote ndis",
    "usb ethernet",
    "usb ncm",
    "cdc ncm",
    "cdc ecm",
    "gadget",
    "usb lan",
    "caddx",
    "walksnail",
    "ascent",
    "vrx",
)

# Ports open on a stock VRX and useful as reachability probes.
PROBE_TCP_PORTS = (22, 554, 80, 23)

_PS_PRELUDE = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n"


class NetworkError(RuntimeError):
    """Network inspection or configuration failed."""


# --------------------------------------------------------------------------
# Data types
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class IPConfig:
    address: ipaddress.IPv4Address
    prefix: int
    origin: str = ""

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(f"{self.address}/{self.prefix}", strict=False)

    @property
    def cidr(self) -> str:
        return f"{self.address}/{self.prefix}"

    def contains(self, other: ipaddress.IPv4Address) -> bool:
        return other in self.network


@dataclass
class Adapter:
    ifindex: int
    name: str
    description: str
    status: str
    mac: str = ""
    link_speed: str = ""
    ips: list[IPConfig] = field(default_factory=list)
    guid: str = ""

    @property
    def is_up(self) -> bool:
        return self.status.strip().lower() == "up"

    @property
    def is_rndis(self) -> bool:
        text = f"{self.name} {self.description}".lower()
        return any(word in text for word in RNDIS_KEYWORDS)

    @property
    def label(self) -> str:
        return f"{self.description or self.name} ({self.name})"

    def usable_ips(self, target: ipaddress.IPv4Address = VRX_IP) -> list[IPConfig]:
        return [ip for ip in self.ips if ip.contains(target)]

    def sorted_ips(self) -> list[IPConfig]:
        return sorted(self.ips, key=lambda ip: (ip.address == VRX_IP, ip.address))


@dataclass(frozen=True)
class Reachability:
    present: bool
    method: str
    detail: str
    elapsed_ms: int = 0


@dataclass
class NetworkState:
    adapters: list[Adapter]
    adapter: Adapter | None
    host_ip: ipaddress.IPv4Address | None
    problem: str | None
    problem_detail: str = ""
    proposed_host_ip: ipaddress.IPv4Address | None = None
    proposed_prefix: int = USB_PREFIX

    @property
    def configured(self) -> bool:
        return self.problem is None and self.host_ip is not None


# --------------------------------------------------------------------------
# PowerShell helpers
# --------------------------------------------------------------------------


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - ctypes probing is best-effort
        return False


@dataclass
class PsResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def text(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()


def _decode_ps_output(raw: bytes) -> str:
    """Decode PowerShell output, which may be UTF-8 or UTF-16."""
    if not raw:
        return ""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", "replace")
    # UTF-16LE without a BOM looks like ASCII with interleaved NUL bytes.
    if raw.count(b"\x00") > len(raw) // 4:
        return raw.decode("utf-16-le", "replace")
    return raw.decode("utf-8", "replace")


def _run_ps(script: str, timeout: float = 60.0) -> PsResult:
    if not is_windows():
        raise NetworkError("PowerShell is only available on Windows")

    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as error:
        raise NetworkError("PowerShell command timed out") from error

    return PsResult(
        returncode=completed.returncode,
        stdout=_decode_ps_output(completed.stdout).strip(),
        stderr=_decode_ps_output(completed.stderr).strip(),
    )


def _run_ps_json(script: str, timeout: float = 60.0):
    result = _run_ps(_PS_PRELUDE + script, timeout)
    if result.returncode != 0:
        raise NetworkError(result.stderr or result.stdout or "PowerShell failed")
    text = result.stdout.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise NetworkError(f"unexpected PowerShell output: {text[:300]}") from error


def _read_admin_log(log_path: Path, attempts: int = 5, delay: float = 0.2) -> str | None:
    """Read the elevated task log, retrying while Windows still holds it."""
    for attempt in range(1, attempts + 1):
        try:
            return log_path.read_text(encoding="utf-8-sig", errors="replace").strip()
        except FileNotFoundError:
            return ""
        except OSError:
            if attempt >= attempts:
                return None
            time.sleep(delay)
    return None


def _run_admin(script: str, timeout: float = 180.0) -> tuple[bool, str]:
    """Run a PowerShell script directly when elevated, otherwise through UAC."""
    if not is_windows():
        return False, "Windows is required"

    if is_admin():
        result = _run_ps(_PS_PRELUDE + "$ErrorActionPreference='Stop'\n" + script, timeout)
        return result.returncode == 0, result.text

    temp_dir = Path(tempfile.mkdtemp(prefix="vrx_unlock_"))
    script_path = temp_dir / "task.ps1"
    log_path = temp_dir / "result.txt"
    # Create the log from this (unelevated) process so it inherits our ACLs;
    # an elevated process may leave a DACL this process cannot read.
    log_path.touch()
    escaped_script = str(script_path).replace("'", "''")
    escaped_log = str(log_path).replace("'", "''")

    script_path.write_text(
        "$ErrorActionPreference='Stop'\n"
        "try {\n"
        "  & {\n"
        f"{script}\n"
        "  } *> '" + escaped_log + "'\n"
        "  exit 0\n"
        "} catch {\n"
        "  ('ERROR: ' + $_.Exception.Message) | "
        "Out-File -FilePath '" + escaped_log + "' -Append -Encoding utf8\n"
        "  exit 1\n"
        "}\n",
        encoding="utf-8-sig",
    )

    outer = (
        "$ErrorActionPreference='Stop'\n"
        "try {\n"
        "  $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs "
        "-WindowStyle Hidden -Wait -PassThru "
        f"-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','{escaped_script}')\n"
        "  exit $p.ExitCode\n"
        "} catch {\n"
        "  Write-Error $_.Exception.Message\n"
        "  exit 1\n"
        "}\n"
    )

    try:
        result = _run_ps(outer, timeout)
        log_text = _read_admin_log(log_path)
        if log_text is None:
            detail = f": {result.text}" if result.text else ""
            message = "the elevated operation finished but its output was unreadable" + detail
        else:
            message = log_text or result.text or "the elevated operation did not run"
        return result.returncode == 0, message
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


# --------------------------------------------------------------------------
# Adapter discovery
# --------------------------------------------------------------------------


def parse_adapters_json(raw) -> list[Adapter]:
    """Convert ``Get-NetAdapter`` JSON into :class:`Adapter` objects."""
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = [raw]

    adapters: list[Adapter] = []
    for item in raw:
        if not isinstance(item, dict):
            continue

        raw_ips = item.get("ips") or []
        if isinstance(raw_ips, dict):
            raw_ips = [raw_ips]

        ips: list[IPConfig] = []
        for raw_ip in raw_ips:
            if not isinstance(raw_ip, dict):
                continue
            try:
                address = ipaddress.IPv4Address(str(raw_ip.get("IPAddress", "")))
                prefix = int(raw_ip.get("PrefixLength", 24))
            except (ipaddress.AddressValueError, ValueError, TypeError):
                continue
            ips.append(
                IPConfig(
                    address=address,
                    prefix=prefix,
                    origin=str(raw_ip.get("PrefixOrigin", "")),
                )
            )

        try:
            ifindex = int(item.get("ifIndex", 0))
        except (TypeError, ValueError):
            continue

        adapters.append(
            Adapter(
                ifindex=ifindex,
                name=str(item.get("name", "")),
                description=str(item.get("description", "")),
                status=str(item.get("status", "")),
                mac=str(item.get("mac", "")),
                link_speed=str(item.get("linkSpeed", "")),
                ips=ips,
                guid=str(item.get("guid") or ""),
            )
        )
    return adapters


def list_adapters() -> list[Adapter]:
    """Return every Windows network adapter with its IPv4 configuration."""
    adapters = _list_adapters_once()
    if not adapters:
        # WMI/PowerShell occasionally reports nothing right after the RNDIS
        # gadget re-enumerates; one retry avoids a false "adapter not found".
        time.sleep(0.5)
        adapters = _list_adapters_once()
    return adapters


def _list_adapters_once() -> list[Adapter]:
    script = r"""
$rows = @(
  Get-NetAdapter | Sort-Object ifIndex | ForEach-Object {
    $a = $_
    $ips = @(
      Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object IPAddress, PrefixLength, PrefixOrigin
    )
    [pscustomobject]@{
      ifIndex     = [int]$a.ifIndex
      name        = [string]$a.Name
      description = [string]$a.InterfaceDescription
      status      = [string]$a.Status
      mac         = [string]$a.MacAddress
      linkSpeed   = [string]$a.LinkSpeed
      guid        = [string]$a.InterfaceGuid
      ips         = @($ips)
    }
  }
)
ConvertTo-Json -InputObject $rows -Depth 6 -Compress
"""
    return parse_adapters_json(_run_ps_json(script))


def select_adapter(
    adapters: Sequence[Adapter], target: ipaddress.IPv4Address = VRX_IP
) -> Adapter | None:
    """Pick the adapter most likely to be the VRX USB Ethernet interface."""
    up = [adapter for adapter in adapters if adapter.is_up]

    rndis_in_subnet = [a for a in up if a.is_rndis and a.usable_ips(target)]
    if rndis_in_subnet:
        return max(rndis_in_subnet, key=lambda adapter: adapter.ifindex)

    rndis_up = [adapter for adapter in up if adapter.is_rndis]
    if rndis_up:
        return max(rndis_up, key=lambda adapter: adapter.ifindex)

    in_subnet = [adapter for adapter in up if adapter.usable_ips(target)]
    if in_subnet:
        return max(in_subnet, key=lambda adapter: adapter.ifindex)

    rndis_any = [adapter for adapter in adapters if adapter.is_rndis]
    if rndis_any:
        return max(rndis_any, key=lambda adapter: (adapter.is_up, adapter.ifindex))

    return None


def local_addresses(adapters: Sequence[Adapter]) -> set[ipaddress.IPv4Address]:
    used: set[ipaddress.IPv4Address] = set()
    for adapter in adapters:
        used.update(ip.address for ip in adapter.ips)
    return used


def choose_available_host_ip(
    adapters: Sequence[Adapter],
    target: ipaddress.IPv4Address = VRX_IP,
    preferred: ipaddress.IPv4Address = PREFERRED_HOST_IP,
) -> ipaddress.IPv4Address:
    used = local_addresses(adapters)
    if preferred != target and preferred not in used:
        return preferred

    for last in (100, 101, 104, 105, 106, 107, 108, 109, 110, 50, 51, 60, 61, 62):
        candidate = ipaddress.IPv4Address(int(USB_SUBNET.network_address) + last)
        if candidate != target and candidate not in used:
            return candidate

    raise NetworkError("could not find a free address in 192.168.3.0/24")


def _pick_host_ip(
    adapter: Adapter, target: ipaddress.IPv4Address = VRX_IP
) -> ipaddress.IPv4Address | None:
    candidates = [ip.address for ip in adapter.usable_ips(target)]
    if not candidates:
        return None
    candidates.sort(
        key=lambda address: (
            address == target,
            address != PREFERRED_HOST_IP,
            int(address),
        )
    )
    return candidates[0]


# --------------------------------------------------------------------------
# State analysis
# --------------------------------------------------------------------------


def analyze(adapters: Sequence[Adapter] | None = None) -> NetworkState:
    """Inspect the RNDIS adapter and decide whether the host is usable."""
    if adapters is None and not is_windows():
        return NetworkState(
            adapters=[],
            adapter=None,
            host_ip=None,
            problem="not-windows",
            problem_detail="automatic USB network checks are only available on Windows",
        )

    adapters = list(list_adapters() if adapters is None else adapters)
    adapter = select_adapter(adapters)

    if adapter is None:
        return NetworkState(
            adapters=adapters,
            adapter=None,
            host_ip=None,
            problem="no-adapter",
            problem_detail=(
                "no USB Ethernet / RNDIS adapter found - connect the VRX with a "
                "USB data cable and power it on"
            ),
            proposed_host_ip=choose_available_host_ip(adapters),
        )

    if not adapter.is_up:
        return NetworkState(
            adapters=adapters,
            adapter=adapter,
            host_ip=None,
            problem="adapter-down",
            problem_detail=(
                f"{adapter.label} is {adapter.status or 'not connected'} - "
                "check the USB cable and the VRX power"
            ),
            proposed_host_ip=choose_available_host_ip(adapters),
        )

    host_ip = _pick_host_ip(adapter)
    if host_ip is None:
        return NetworkState(
            adapters=adapters,
            adapter=adapter,
            host_ip=None,
            problem="not-in-subnet",
            problem_detail=f"{adapter.label} has no address in {USB_SUBNET} (VRX is {VRX_IP})",
            proposed_host_ip=choose_available_host_ip(adapters),
        )

    if host_ip == VRX_IP:
        return NetworkState(
            adapters=adapters,
            adapter=adapter,
            host_ip=None,
            problem="ip-conflict",
            problem_detail=f"this PC is using {VRX_IP}, which is the VRX's own address",
            proposed_host_ip=choose_available_host_ip(adapters),
        )

    # A prefix wider than /24 still works as long as it contains the VRX.
    return NetworkState(
        adapters=adapters,
        adapter=adapter,
        host_ip=host_ip,
        problem=None,
        problem_detail="",
    )


def describe_state(state: NetworkState) -> list[tuple[str, str, str | None]]:
    """Build (label, value, status) rows; status is "ok", "bad", or None."""
    rows: list[tuple[str, str, str | None]] = []

    if state.adapter is None:
        rows.append(("USB adapter", "not found", "bad"))
    else:
        status_text = state.adapter.status or "unknown"
        rows.append(
            (
                "USB adapter",
                f"{state.adapter.label}  [{status_text}]",
                "ok" if state.adapter.is_up else "bad",
            )
        )

    if state.host_ip is not None:
        rows.append(("Host address", str(state.host_ip), "ok"))
    elif state.adapter is not None and state.adapter.ips:
        rows.append(
            ("Host address", ", ".join(ip.cidr for ip in state.adapter.sorted_ips()), "bad")
        )
    else:
        rows.append(("Host address", "none", "bad"))

    rows.append(("VRX address", str(VRX_IP), None))

    if state.problem is None:
        rows.append(("USB network", f"ready ({USB_SUBNET})", "ok"))
    else:
        rows.append(("USB network", state.problem_detail, "bad"))

    return rows


# --------------------------------------------------------------------------
# Reachability
# --------------------------------------------------------------------------


def ping(address: ipaddress.IPv4Address, timeout_ms: int = 1200) -> tuple[bool, int]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            ["ping", "-4", "-n", "1", "-w", str(timeout_ms), str(address)],
            capture_output=True,
            timeout=(timeout_ms / 1000.0) + 3.0,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, 0
    elapsed = int((time.monotonic() - started) * 1000)
    return completed.returncode == 0, elapsed


def probe_tcp(
    address: ipaddress.IPv4Address,
    ports: Sequence[int] = PROBE_TCP_PORTS,
    timeout: float = 0.45,
) -> list[int]:
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.create_connection((str(address), port), timeout=timeout):
                open_ports.append(port)
        except OSError:
            continue
    return open_ports


def check_reachability(address: ipaddress.IPv4Address = VRX_IP) -> Reachability:
    """Check whether the VRX answers; ICMP first, then a TCP probe."""
    started = time.monotonic()
    ok, ping_ms = ping(address)
    if ok:
        return Reachability(True, "ICMP", f"ping reply in {ping_ms} ms", int(
            (time.monotonic() - started) * 1000
        ))

    open_ports = probe_tcp(address)
    if open_ports:
        detail = "open TCP port(s): " + ", ".join(str(port) for port in open_ports)
        return Reachability(True, "TCP", detail, int(
            (time.monotonic() - started) * 1000
        ))

    return Reachability(
        False,
        "none",
        "no ICMP reply and no open probe ports",
        int((time.monotonic() - started) * 1000),
    )


# --------------------------------------------------------------------------
# Fixes
# --------------------------------------------------------------------------


def netmask_for(prefix: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=False).netmask)


def manual_static_ip_command(
    adapter: Adapter, host_ip: ipaddress.IPv4Address, prefix: int = USB_PREFIX
) -> str:
    return (
        f'netsh interface ipv4 set address name="{adapter.name}" '
        f"static {host_ip} {netmask_for(prefix)}"
    )


def apply_static_ip(
    adapter: Adapter,
    host_ip: ipaddress.IPv4Address,
    prefix: int = USB_PREFIX,
) -> tuple[bool, str]:
    """Replace the adapter's IPv4 config with a static address (elevated)."""
    if not adapter.is_rndis:
        return False, "automatic IPv4 changes require a USB network adapter"
    try:
        adapter_guid = UUID(adapter.guid)
    except ValueError:
        return False, "the USB network adapter has no valid interface GUID"

    adapter_name = adapter.name.replace("'", "''")
    script = f"""
$idx = {adapter.ifindex}
$a = Get-NetAdapter -InterfaceIndex $idx -ErrorAction Stop
if ([guid]$a.InterfaceGuid -ne [guid]'{adapter_guid}') {{
  throw 'the selected USB network adapter changed'
}}
Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
foreach ($ip in @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue)) {{
  try {{
    Remove-NetIPAddress -IPAddress $ip.IPAddress -InterfaceIndex $idx -Confirm:$false -ErrorAction Stop
  }} catch {{
    Write-Output ('WARN: could not remove ' + $ip.IPAddress + ': ' + $_.Exception.Message)
  }}
}}
New-NetIPAddress -InterfaceIndex $idx -IPAddress '{host_ip}' -PrefixLength {prefix} -ErrorAction Stop | Out-Null
Remove-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -Confirm:$false -ErrorAction SilentlyContinue
Write-Output ('OK: set {host_ip}/{prefix} on {adapter_name}')
"""
    return _run_admin(script)


# --------------------------------------------------------------------------
# Saved state / restore
# --------------------------------------------------------------------------


def save_network_state(adapter: Adapter, *, overwrite: bool = False) -> Path:
    """Snapshot the adapter's IPv4 config before changing it."""
    try:
        adapter_guid = UUID(adapter.guid)
    except ValueError as error:
        raise NetworkError("the USB network adapter has no valid interface GUID") from error

    if STATE_PATH.exists() and not overwrite:
        try:
            existing = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and existing.get("adapter_guid") == str(adapter_guid):
                return STATE_PATH
        except (OSError, json.JSONDecodeError):
            pass

    script = f"""
$idx = {adapter.ifindex}
$a = Get-NetAdapter -InterfaceIndex $idx -ErrorAction Stop
if ([guid]$a.InterfaceGuid -ne [guid]'{adapter_guid}') {{
  throw 'the selected USB network adapter changed'
}}
$iface = Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop
$ips = @(Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  ForEach-Object {{ "$($_.IPAddress)/$($_.PrefixLength)" }})
$gateways = @(Get-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  ForEach-Object {{ $_.NextHop }})
$dns = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  ForEach-Object {{ $_.ServerAddresses }})
[pscustomobject]@{{
  adapter_name = [string]$a.Name
  adapter_guid = '{adapter_guid}'
  ifindex      = $idx
  dhcp         = ([string]$iface.Dhcp)
  ips          = @($ips)
  gateways     = @($gateways)
  dns          = @($dns)
}} | ConvertTo-Json -Depth 4 -Compress
"""
    raw = _run_ps_json(script)
    if not isinstance(raw, dict):
        raise NetworkError("could not read the current network configuration")

    raw["saved_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STATE_PATH.write_text(json.dumps(raw, indent=2), encoding="utf-8")
    except OSError as error:
        raise NetworkError(f"could not write network state: {error}") from error
    return STATE_PATH


def load_network_state() -> dict | None:
    if not STATE_PATH.exists():
        return None
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return state if isinstance(state, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def describe_saved_state(state: dict) -> str:
    ips = ", ".join(state.get("ips") or []) or "none"
    mode = "DHCP" if str(state.get("dhcp", "")).lower() == "enabled" else "static"
    return f"{state.get('adapter_name', '?')}: {mode}, {ips}"


def restore_network_state(state: dict | None = None) -> tuple[bool, str]:
    """Put a saved adapter configuration back (elevated)."""
    state = state or load_network_state()
    if not state:
        return False, "no saved network state"

    try:
        adapter_guid = UUID(str(state.get("adapter_guid") or ""))
    except ValueError:
        return (
            False,
            "saved state has no valid adapter GUID; restore the adapter manually",
        )

    dhcp = str(state.get("dhcp", "")).lower() == "enabled"
    ips = [str(value) for value in (state.get("ips") or [])]
    try:
        interfaces = [ipaddress.IPv4Interface(value) for value in ips]
        gateways = [ipaddress.IPv4Address(value) for value in (state.get("gateways") or [])]
        dns = [ipaddress.IPv4Address(value) for value in (state.get("dns") or [])]
    except (ValueError, TypeError):
        return False, "saved state contains invalid IPv4 settings"

    lines: list[str] = [
        "$a = @(Get-NetAdapter -ErrorAction Stop | Where-Object { "
        f"[guid]$_.InterfaceGuid -eq [guid]'{adapter_guid}' }})",
        "if ($a.Count -ne 1) { throw 'saved USB network adapter could not be identified' }",
        "$idx = $a[0].ifIndex",
        "Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Disabled "
        "-ErrorAction Stop",
        "Get-NetIPAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "ForEach-Object { Remove-NetIPAddress -IPAddress $_.IPAddress -InterfaceIndex $idx "
        "-Confirm:$false -ErrorAction Stop }",
    ]

    if dhcp:
        lines.append(
            "Set-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -Dhcp Enabled "
            "-ErrorAction Stop"
        )
        lines.append("Write-Output 'OK: DHCP enabled'")
    else:
        for interface in interfaces:
            lines.append(
                f"New-NetIPAddress -InterfaceIndex $idx -IPAddress '{interface.ip}' "
                f"-PrefixLength {interface.network.prefixlen} -ErrorAction Stop | Out-Null"
            )
        for gateway in gateways:
            lines.append(
                f"New-NetRoute -InterfaceIndex $idx -DestinationPrefix '0.0.0.0/0' "
                f"-NextHop '{gateway}' -ErrorAction Stop | Out-Null"
            )
        if dns:
            dns_list = ",".join(f"'{server}'" for server in dns)
            lines.append(
                f"Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses @({dns_list}) "
                "-ErrorAction Stop"
            )
        lines.append("Write-Output 'OK: previous configuration restored'")

    ok, message = _run_admin("\n".join(lines))
    if ok:
        try:
            STATE_PATH.unlink(missing_ok=True)
        except OSError:
            pass
    return ok, message
