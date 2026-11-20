"""Unit tests for the VRX unlock protocol and RNDIS decision logic."""

from __future__ import annotations

import ipaddress
import unittest

import vrx_unlock
import vrx_unlock_network as net


def make_adapter(
    *,
    ifindex: int = 63,
    name: str = "Ethernet 4",
    description: str = "Remote NDIS Compatible Device #2",
    status: str = "Up",
    ips: tuple[str, ...] = (),
    guid: str = "{00000000-0000-0000-0000-000000000001}",
) -> net.Adapter:
    return net.Adapter(
        ifindex=ifindex,
        name=name,
        description=description,
        status=status,
        ips=[
            net.IPConfig(ipaddress.IPv4Address(value.split("/")[0]), int(value.split("/")[1]))
            for value in ips
        ],
        guid=guid,
    )


class PacketTests(unittest.TestCase):
    def test_debug3_frame_is_exact(self) -> None:
        packet = vrx_unlock.build_key_packet("debug3")
        self.assertEqual(
            packet.hex(" ").upper(),
            "FE EF 22 00 04 40 09 00 00 00 49 0D 0A",
        )

    def test_checksum_covers_payload_only(self) -> None:
        self.assertEqual(vrx_unlock.calculate_checksum(bytes([0x40, 0x09, 0, 0])), b"\x00\x49")
        self.assertEqual(vrx_unlock.calculate_checksum(b"\xff\xff"), b"\x01\xfe")
        self.assertEqual(vrx_unlock.calculate_checksum(b""), b"\x00\x00")

    def test_round_trip(self) -> None:
        packet = vrx_unlock.assemble_packet(0x22, bytes([0x50, 1, 12, 1, 0, 0, 0, 0]))
        command, payload = vrx_unlock.parse_packet(packet)
        self.assertEqual(command, 0x22)
        self.assertEqual(payload, bytes([0x50, 1, 12, 1, 0, 0, 0, 0]))

    def test_little_endian_length_is_rejected(self) -> None:
        packet = bytearray(vrx_unlock.build_key_packet("debug3"))
        packet[3], packet[4] = packet[4], packet[3]
        with self.assertRaises(vrx_unlock.ProtocolError):
            vrx_unlock.parse_packet(bytes(packet))

    def test_checksum_mismatch_is_rejected(self) -> None:
        packet = bytearray(vrx_unlock.build_key_packet("debug3"))
        packet[9] ^= 0xFF
        with self.assertRaises(vrx_unlock.ProtocolError):
            vrx_unlock.parse_packet(bytes(packet))

    def test_bad_tail_is_rejected(self) -> None:
        packet = bytearray(vrx_unlock.build_key_packet("debug3"))
        packet[-1] = 0x00
        with self.assertRaises(vrx_unlock.ProtocolError):
            vrx_unlock.parse_packet(bytes(packet))

    def test_truncated_frame_is_rejected(self) -> None:
        with self.assertRaises(vrx_unlock.ProtocolError):
            vrx_unlock.parse_packet(bytes.fromhex("FE EF 22 00 04"))

    def test_all_keys_build(self) -> None:
        for name in vrx_unlock.KEYS:
            command, payload = vrx_unlock.parse_packet(vrx_unlock.build_key_packet(name))
            self.assertEqual(command, vrx_unlock.WRITE_COMMAND)
            self.assertEqual(payload[0], 0x40)
            self.assertEqual(len(payload), 4)

    def test_debug3_key_table(self) -> None:
        self.assertEqual(vrx_unlock.KEYS["debug3"], (9, 0))
        self.assertEqual(vrx_unlock.UNLOCK_KEY, "debug3")

    def test_read_packet_shape(self) -> None:
        packet = vrx_unlock.build_read_packet(0x52)
        command, payload = vrx_unlock.parse_packet(packet)
        self.assertEqual(command, vrx_unlock.READ_COMMAND)
        self.assertEqual(payload[0], 0x52)
        self.assertEqual(len(payload), 8)

    def test_decode_wireless_status(self) -> None:
        # Real reply observed from the VRX: 25 Mbps, 1 ms delay.
        raw = bytes.fromhex("FE EF A2 00 08 52 CF CB 25 19 01 00 00 02 2B 0D 0A")
        _command, payload = vrx_unlock.parse_packet(raw)
        decoded = vrx_unlock.decode_payload(payload)
        self.assertEqual(decoded["type"], "wireless_status")
        self.assertEqual(decoded["rssi1"], 0xCF)
        self.assertEqual(decoded["rssi2"], 0xCB)
        self.assertEqual(decoded["data_rate_mbps"], 0x19)
        self.assertEqual(decoded["delay_ms"], 1)
        self.assertFalse(decoded["connected"])

    def test_decode_frequency(self) -> None:
        payload = bytes([0x51, 1, 3, 1, 0, 0, 0, 0])
        decoded = vrx_unlock.decode_payload(payload)
        self.assertEqual(decoded, {"type": "frequency", "band": "B", "channel": 3, "hopping": True})

    def test_decode_power_bitmap(self) -> None:
        payload = bytes([0x53, 5, 0x01, 0xFF, 0xFF, 0xFF, 0, 0])
        decoded = vrx_unlock.decode_payload(payload)
        self.assertEqual(decoded["power_index"], 5)
        self.assertEqual(decoded["settable_indices"][0], 0)
        self.assertIn(8, decoded["settable_indices"])
        self.assertNotIn(1, decoded["settable_indices"])

    def test_unknown_key_raises(self) -> None:
        with self.assertRaises(ValueError):
            vrx_unlock.build_key_packet("nope")


class NetworkDecisionTests(unittest.TestCase):
    def test_rndis_detection(self) -> None:
        adapter = make_adapter()
        self.assertTrue(adapter.is_rndis)
        self.assertFalse(make_adapter(description="Intel Wi-Fi 6E AX210").is_rndis)

    def test_configured_subnet(self) -> None:
        state = net.analyze([make_adapter(ips=("192.168.3.50/24",))])
        self.assertTrue(state.configured)
        self.assertEqual(str(state.host_ip), "192.168.3.50")

    def test_link_local_needs_fix(self) -> None:
        state = net.analyze([make_adapter(ips=("169.254.54.17/16",))])
        self.assertFalse(state.configured)
        self.assertEqual(state.problem, "not-in-subnet")
        self.assertEqual(str(state.proposed_host_ip), "192.168.3.103")

    def test_missing_adapter(self) -> None:
        state = net.analyze([])
        self.assertFalse(state.configured)
        self.assertEqual(state.problem, "no-adapter")

    def test_adapter_down(self) -> None:
        state = net.analyze([make_adapter(status="Disconnected", ips=("192.168.3.50/24",))])
        self.assertEqual(state.problem, "adapter-down")

    def test_ip_conflict_with_vrx(self) -> None:
        state = net.analyze([make_adapter(ips=("192.168.3.102/24",))])
        self.assertEqual(state.problem, "ip-conflict")

    def test_describe_rows(self) -> None:
        state = net.analyze([make_adapter(ips=("169.254.54.17/16",))])
        rows = {label: (value, status) for label, value, status in net.describe_state(state)}
        self.assertEqual(rows["USB adapter"][1], "ok")
        self.assertEqual(rows["Host address"][1], "bad")
        self.assertEqual(rows["USB network"][1], "bad")

    def test_manual_command(self) -> None:
        adapter = make_adapter(ips=("169.254.54.17/16",))
        command = net.manual_static_ip_command(
            adapter, ipaddress.IPv4Address("192.168.3.103"), 24
        )
        self.assertIn('name="Ethernet 4"', command)
        self.assertIn("static 192.168.3.103 255.255.255.0", command)

    def test_parse_adapters_json_single_object(self) -> None:
        raw = {
            "ifIndex": 63,
            "name": "Ethernet 4",
            "description": "Remote NDIS Compatible Device #2",
            "status": "Up",
            "guid": "{00000000-0000-0000-0000-000000000001}",
            "ips": {"IPAddress": "192.168.3.103", "PrefixLength": 24},
        }
        adapters = net.parse_adapters_json(raw)
        self.assertEqual(len(adapters), 1)
        self.assertEqual(adapters[0].ips[0].cidr, "192.168.3.103/24")


if __name__ == "__main__":
    unittest.main()
