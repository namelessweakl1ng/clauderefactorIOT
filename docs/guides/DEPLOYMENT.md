# Multi-device deployment

TRAPSIG runs **16 device personas** across a small fleet of sensor devices, all
managed from one place. The reference layout uses one Raspberry Pi (Pi OS Lite)
and three hosts that may be Linux or Windows, in any mix.

```
                    isolated lab switch / VLAN (no route to production or the Internet)
   ┌───────────────┬───────────────┬────────────────┬────────────────┬─────────────────┐
   │ pi-ot         │ host-home     │ host-office    │ host-server    │ analysis host   │
   │ Pi OS Lite    │ Linux/Windows │ Linux/Windows  │ Linux/Windows  │ (one of the     │
   │ PLC, S7, ATG, │ router, cam,  │ workstation,   │ edge server,   │  hosts, or a    │
   │ VFD, AHU, BMS │ DVR, gateway  │ printer, VoIP, │ HMI panel      │  laptop)        │
   │               │               │ NAS            │                │ ES · Logstash · │
   │ agent.py ─────┼── agent.py ───┼── agent.py ────┼── agent.py ────┼─▶ API · console │
   └───────────────┴───────────────┴────────────────┴────────────────┴─────────────────┘
       events → Logstash HTTP :5045      assignment/heartbeat/posture ↔ API :8000
```

Each device runs **one program**, `sensor/honeypots/agent.py`. It is
standard-library Python 3.11+ only, so there is nothing to `pip install`.
The agent:

- pulls the personas assigned to its `sensor_id` from the backend and runs them
  on their real ports (Modbus 502, S7 102, BACnet 47808, SNMP 161, VNC 5900,
  RDP 3389, and so on);
- applies assignment changes **without a restart** within one poll (default 30 s);
- ships persona events to Logstash, and keeps running from a cached assignment if
  the backend is down;
- sends heartbeats and enforces the RL hardening decisions.

You manage everything from the console: **Sensors & Personas → Fleet**. Tick
personas per device, optionally give a persona its own IP, then save. The backend
validates the assignment before the agents see it: it rejects unknown personas,
duplicates and port clashes on the same address.

## 0. Safety first

These are honeypots. Put every sensor on a **dedicated, isolated lab network**
(its own switch, or a VLAN with no route to your home/office LAN or the
Internet), and run attack scenarios only from inside it. The runner refuses
targets outside `LAB_SUBNET`. Do not port-forward these services. The
decoys never execute anything: shells are emulated, downloads are never fetched,
TFTP refuses transfers and Redis "writes" are discarded. Even so, keep them
unreachable from anything you care about.

## 1. Analysis host

Pick a machine on the lab network. It can be one of the three hosts, as long as
attacks are not launched from the same address (see §6).

```bash
cp .env.example .env    # set ELASTIC_PASSWORD, API_KEYS (incl. a sensor:<key>), TRAPSIG_INGEST_PASSWORD
docker compose up -d elasticsearch logstash backend frontend
```

`sensor/fleet.toml` is the default layout. It is mounted into the backend and
served until you edit a device in the console. Logstash listens for agents on
**5045** (HTTP, basic auth with `TRAPSIG_INGEST_USER`/`TRAPSIG_INGEST_PASSWORD`).

## 2. Each sensor device

Copy the `sensor/honeypots/` folder to the device, then create its config from
`sensor/trapsig-sensor.example.toml`. Only `sensor_id` differs between devices:

```toml
sensor_id = "host-office"                 # pi-ot | host-home | host-office | host-server
backend_url = "http://192.168.50.5:8000"
api_key = "<the sensor:<key> from API_KEYS>"
ingest_url = "http://192.168.50.5:5045"
ingest_user = "trapsig"
ingest_password = "<TRAPSIG_INGEST_PASSWORD>"
```

Check it first. This validates the config, fetches the assignment, and lists
every port it will open together with anything already using it:

```bash
python3 agent.py check --config trapsig-sensor.toml
```

### Raspberry Pi OS Lite / Linux

```bash
sudo useradd --system --home /var/lib/trapsig-sensor --create-home trapsig
sudo mkdir -p /opt/trapsig && sudo cp -r honeypots /opt/trapsig/ && sudo cp trapsig-sensor.toml /opt/trapsig/
sudo python3 /opt/trapsig/honeypots/agent.py install --config /opt/trapsig/trapsig-sensor.toml --apply
sudo systemctl status trapsig-sensor
```

The unit runs as the unprivileged `trapsig` user. `AmbientCapabilities=CAP_NET_BIND_SERVICE`
lets it bind ports below 1024 without root, and the unit applies systemd
sandboxing (`ProtectSystem=strict`, `NoNewPrivileges`, and so on). Pi OS Lite
(Bookworm) ships Python 3.11, which is enough.

### Windows 10/11

Install Python 3.11+ from python.org (check "Add to PATH"). Then, in an
Administrator PowerShell:

```powershell
mkdir C:\trapsig; Copy-Item -Recurse honeypots C:\trapsig\; Copy-Item trapsig-sensor.toml C:\trapsig\
python C:\trapsig\honeypots\agent.py install --config C:\trapsig\trapsig-sensor.toml --apply
# Allow the decoy ports on the lab network profile only:
New-NetFirewallRule -DisplayName "TRAPSIG decoys" -Direction Inbound -Program (Get-Command python).Source -Action Allow -Profile Private
```

This registers a start-up scheduled task that runs as `NT AUTHORITY\LocalService`,
a low-privilege service account. Windows does not restrict ports below 1024.

**Windows port clashes.** Windows may already own some decoy ports. RDP (3389)
is taken if Remote Desktop is on, and SNMP (161) if the SNMP service is
installed. `agent.py check` shows these. Either disable the Windows service, move
that persona to a Linux device in the console, or give it a bind IP (§3). A
persona that cannot bind one port still serves its other ports, and the
heartbeat reports the failure, so the console shows it in amber.

## 3. One IP per device (optional, more realistic)

By default all personas on a device share that device's address. To make, say,
the printer and the VoIP phone look like separate hosts, add extra addresses to
the device and set `bind_ip` per persona in the console.

| OS | Add an address (example 192.168.50.41/24) |
|---|---|
| Pi OS Lite (NetworkManager) | `sudo nmcli con mod "Wired connection 1" +ipv4.addresses 192.168.50.41/24 && sudo nmcli con up "Wired connection 1"` |
| Debian/Ubuntu (temporary) | `sudo ip addr add 192.168.50.41/24 dev eth0` (make it permanent in netplan / NetworkManager) |
| Windows (static NIC) | `New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.50.41 -PrefixLength 24` |

With separate addresses, two personas on the same device can even use the same
port, for example two VNC servers on 5900. The backend checks conflicts per
address, and treats an empty `bind_ip` (all addresses) as clashing with every
alias on that device.

## 4. Managing the fleet

- **Console → Sensors & Personas → Fleet.** One card per device shows the
  assigned personas with their live status, listening/total services and event
  counts, plus anything still running that is no longer assigned. Save, and the
  device applies the change on its next poll.
- **API.** `GET /fleet` lists devices, `PUT /fleet/<sensor_id>` (admin) changes
  one, and `GET /fleet/<sensor_id>/assignment` is what the agents read (the
  sensor role may read it).
- **Persona definitions** (banners, credentials, registers…) are edited per
  persona (`PUT /personas/<id>`). The assignment fingerprint includes the
  definition, so agents pick up edits on their next poll too.

## 5. Default layout (sensor/fleet.toml)

| Device | Personas | Ports |
|---|---|---|
| `pi-ot` (Pi OS Lite) | industrial-plc, s7-plc, tank-gauge, vfd-drive, air-handler, building-controller | Modbus 502, S7 102, SNMP 161/udp, ATG 10001, EtherNet/IP 44818, BACnet 47808/udp, CoAP 5683/udp, web UIs |
| `host-home` | home-router, smart-camera, dvr-recorder, iiot-gateway | HTTP, DNS 53/udp, SSDP 1900/udp, RTSP 554/8554, telnet 23, MQTT |
| `host-office` | ops-workstation, office-printer, voip-phone, nas | RDP 3389, VNC 5900, SNMP 161/udp, HTTP 80, FTP 21, SIP 5060/udp, TFTP 69/udp |
| `host-server` | edge-server, hmi-panel | Redis 6379, VNC 5900, web UIs |

Every persona appears exactly once; the test suite checks that the default
layout has no port conflicts.

## 6. Attacking the fleet (experiments)

Run scenarios from an attacker machine on the lab network that is not itself a
sensor, so attacker and sensor addresses never coincide:

```bash
LAB_SUBNET=192.168.50.0/24 python -m attacks.runner.run s7-plc-stop --target 192.168.50.10
```

The 67 scenarios cover every persona protocol (see [SCENARIOS.md](../reference/SCENARIOS.md)).
The Experiments page runs them with ground truth and repetitions.

## 7. Scaling notes

- The processor is **incremental**. Each cycle reads only events ingested since
  its watermark, then re-sessionizes just those sources, so cost follows new
  activity rather than index size. It drains backlogs in batches
  (`PROCESSING_BATCH_EVENTS`). The System page shows the last cycle.
- Agents are independent. Adding a device means adding a `[[sensors]]` entry, or
  just running an agent with a new `sensor_id` and assigning it in the console.
- Multiple backend replicas are safe. Leader election picks one writer; the others
  serve the API.
