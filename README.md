# Ascent VRX Unlock

Debug3 key injection for **Caddx / Walksnail Ascent VRX Pro and VRX Max** over
the USB-LAN (RNDIS) link.

The device speaks the documented "Ascent VRX Max" binary frame protocol over
UDP. This tool assembles the frames, checks/repairs the Windows RNDIS adapter,
discovers the VRX, sends the **Debug3 Mode key**, and decodes any replies.

The Debug3 key is a runtime trigger: the tool only sends UDP datagrams and
never writes to the device or its storage.

## Compatibility

| Model | Status |
| --- | --- |
| VRX Pro | supported |
| VRX Max | supported |
| plain VRX / other models | not supported by this tool — unlock from the device instead |

On a **plain VRX** the unlock is done on the hardware: hold the **Rec** button
for **10 seconds**, until the VRX reboots.

Support depends on the device running the **Ctrl UDP service on port 9001**.
The Pro and Max do; a plain VRX was observed with only TCP 22 and 50000 open
and UDP 9001 silently dropped, so Debug3 frames can never reach the app there.
A factory reset does not add the service — it is a firmware capability, not a
setting.

Symptoms on an unsupported unit: ping and ARP work, `discover` finds nothing,
and `unlock` sends frames that get no reply and cause no reboot.

---

## Project layout

```text
vrx_unlock.py            protocol, UDP client, discovery, CLI
vrx_unlock_network.py    RNDIS adapter checks, static IP fix, saved-state restore
AscentVRXUnlock.bat       double-click launcher (finds/installs Python, then runs)
tests/test_vrx_unlock.py packet and network-decision tests
```

No third-party packages. Python 3.10+ standard library only.

---

## Quick start

Double-click **`AscentVRXUnlock.bat`**, or:

```powershell
python vrx_unlock.py
```

That single command:

1. checks the RNDIS adapter and prints its IPv4 state;
2. probes `192.168.3.102` on UDP 9001/9200/9000;
3. sends the Debug3 frame three times and prints any reply.

### If the RNDIS adapter is wrong

Windows falls back to `169.254.x.x` (APIPA) when the VRX provides no DHCP.
Nothing can reach `192.168.3.102` in that state.

```powershell
python vrx_unlock.py net-check       # adapter / address / reachability
python vrx_unlock.py net-fix         # set 192.168.3.103/24 (UAC prompt)
python vrx_unlock.py restore-network # put the previous settings back
```

`net-fix` snapshots the old configuration to
`%LOCALAPPDATA%\AscentVRXUnlock\network_state.json` before changing anything.

Manual equivalent (elevated):

```bat
netsh interface ipv4 set address name="Ethernet 4" static 192.168.3.103 255.255.255.0
```

Any free address in `192.168.3.0/24` works.

---

## Commands

```text
python vrx_unlock.py [options] [command]

Commands
  unlock           send the Debug3 key (default)
  key NAME         up/down/left/right/confirm/pairing/upgrade/
                   recording/back/force-720p60/debug3
  raw HEX          send a write frame with an arbitrary payload, e.g. 40090100
  discover         probe for the device, send no keys
  status           read wireless status (RSSI, rate, delay, link)
  get-frequency    read band / channel / hopping
  get-power        read power index
  net-check        inspect RNDIS adapter, address, and VRX reachability
  net-fix          apply a static 192.168.3.x address (UAC)
  restore-network  restore the settings saved by net-fix (UAC)

Options
  --host IP        skip discovery, target this address
  --port N         Ctrl UDP port (default 9001)
  --ports a,b,c    ports probed during discovery
  --local-ip IP    force the local interface address
  --repeat N       frames to send (default 3)
  --interval SEC   gap between frames (default 0.25)
  --listen SEC     how long to wait for replies (default 2.0)
  --fix-network    auto-apply the static IP when it is wrong
  --no-network-check
  --dry-run        print the frame, send nothing
  --verbose
```

Options work before or after the subcommand.

Examples:

```powershell
python vrx_unlock.py --dry-run                 # verify the frame only
python vrx_unlock.py unlock --repeat 5
python vrx_unlock.py discover --verbose
python vrx_unlock.py --host 192.168.3.102 status
python vrx_unlock.py --fix-network unlock
python vrx_unlock.py key debug3 --repeat 5
python vrx_unlock.py raw 40090100              # same key, press_type=1
```

---

## Protocol

Every datagram carries one frame, multi-byte fields big-endian:

```text
FE EF | CMD (1) | LEN (2) | PAYLOAD (0..65535) | SUM (2) | 0D 0A
```

| Field | Meaning |
| --- | --- |
| `FE EF` | header |
| `0x22` | write (host → device) |
| `0xA2` | read request / response |
| `LEN` | payload byte count |
| `SUM` | 16-bit sum of payload bytes only |
| `0D 0A` | tail |

Debug3 key payload is `40 09 00 00` (`cmd_type 0x40`, key 9, press 0), so the
sent frame is:

```text
FE EF 22 00 04 40 09 00 00 00 49 0D 0A
```

### Key table

| key_num | press_type | Command |
| --- | --- | --- |
| 0 | 0 | `up` |
| 1 | 0 | `down` |
| 2 | 0 | `left` |
| 3 | 0 | `right` |
| 4 | 0 | `confirm` |
| 5 | 0 | `pairing` |
| 5 | 1 | `upgrade` |
| 6 | 0 | `recording` |
| 7 | 0 | `back` |
| 7 | 1 | `force-720p60` |
| 9 | 0 | `debug3` |

### Read responses

`status` (0x52) and friends return decoded fields; for example a live reply:

```text
FE EF A2 00 08 52 CF CB 25 19 01 00 00 02 2B 0D 0A
  rssi1: 207, rssi2: 203, data_rate_mbps: 25, delay_ms: 1, connected: False
```

Key writes are fire-and-forget: the VRX normally sends no ACK, so a missing
reply after `unlock` is expected. Confirm the effect on the HDMI/OSD output.

---

## Tests

```powershell
python -m unittest discover -s tests -v
```

Covers frame assembly, checksum, length/tail validation, the exact Debug3
frame, key table, response decoding, and the RNDIS decision logic (usable
subnet, APIPA, missing/down adapter, IP conflict).

---

## Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| Adapter shows `169.254.x.x` | No DHCP on the RNDIS link. Run `net-fix`. |
| No adapter at all | Charge-only USB-C cable, or the gadget has not enumerated. Replug. |
| `net-check` says "not reachable" | Device still booting, wrong subnet, or firewall. The UDP unlock can still work. |
| `discover` finds nothing | Try `--ports 9001,9000,9200`, or pass `--host`. |
| Device pings but `discover` is always empty | Model/firmware has no Ctrl UDP service. Seen on a plain VRX (TCP 22/50000 only, UDP 9001 silently dropped). Confirm over SSH with `netstat -lunp`. |
| No reply after `unlock` | Expected: key simulation is fire-and-forget. Check HDMI. |
| Window closes on double-click | It pauses on errors and on plain double-clicks; use a terminal to keep output. |

---

## Attribution

- UDP protocol documentation: [CaddxFPV-Tech/Caddx_vrx_max_udp_protocol](https://github.com/CaddxFPV-Tech/Caddx_vrx_max_udp_protocol)
- RNDIS check/fix approach adapted from [TaranUA/AscentVRXRootTool](https://github.com/TaranUA/AscentVRXRootTool) — this project does not import it and is fully standalone.

No warranty. Use at your own risk.
