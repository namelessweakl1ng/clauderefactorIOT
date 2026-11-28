# Final honeypot personas and fidelity

This is the authoritative identity and capability reference for the feature-frozen sensor. Five honeypots expose six logical services; every identity and data value is fictional and bounded for an isolated college laboratory. Because SSH and Telnet both normalize to `service.name: cowrie`, those interactions produce five distinct normalized service names: `cowrie`, `camera`, `iot-service`, `mqtt`, and `router`.

| Service | Fictional device identity | Model / firmware | Protocol / port | Authentication | Interaction and state | Useful telemetry after normalization | Main scenarios / primary detections | Important limitations | Implementation owners |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SSH, Telnet | Velora Edge Gateway | VEG-200 / 2.7.4 | SSH 2222; Telnet 2223 | `root` / `root` | Cowrie low-interaction emulated shell; session-oriented fake filesystem and command telemetry | authentication attempts, session events, commands, source/destination and SSH/Telnet protocol | `ssh-bruteforce` → `BRUTE_FORCE`; `ssh-interaction` → `COMMAND_INTERACTION`; `telnet-auth-attempts` → `BRUTE_FORCE` | No host shell, proxy, QEMU, payload execution, or real device access | `sensor/honeypots/cowrie/`, `sensor/docker-compose.yml` |
| Camera | AsterView Network Camera | CV-210 / 2.4.7 | HTTP / 8081 | `admin` / `admin`, form and compatible Basic | Stateful bounded web persona; expiring in-memory cookie sessions; synthetic pages, status and snapshot | `http.request.method`, `http.user_agent`, `url.path`, authentication username/password and outcome | `camera-recon` → `WEB_ENUMERATION`; `camera-default-creds` → `DEFAULT_CREDENTIALS` | No camera, real stream, firmware processing, device control, or persistent state | `sensor/honeypots/camera/`, `sensor/honeypots/common/` |
| Router | Nexora Wireless Router | NR-1800 / 1.8.3 | HTTP / 8080 | `admin` / `admin`, form and compatible Basic | Stateful bounded web persona; expiring in-memory cookie sessions; synthetic network and client pages | `http.request.method`, `http.user_agent`, `url.path`, authentication username/password and outcome | `router-recon` → `WEB_ENUMERATION`; `router-default-creds` → `DEFAULT_CREDENTIALS` | No routing, DHCP/DNS, radio control, firmware processing, reboot, or persistent configuration | `sensor/honeypots/router/`, `sensor/honeypots/common/` |
| IoT TCP | Velora Edge Controller | VEC-100 / 3.2.1 | Fictional VCP/1.0-style TCP / 9000 | `admin` / `admin` through `AUTH` | Bounded line-oriented `STATUS`, `VERSION`, `INFO`, `HELP`, and `AUTH` command protocol; connection-local interaction | `iot.operation`, authentication username/password and outcome, source/destination | `iot-probe` → `RECONNAISSANCE`; `iot-default-creds` → `DEFAULT_CREDENTIALS` | No shell, GPIO, serial, device control, persistence, or arbitrary commands | `sensor/honeypots/iot_service/`, `sensor/honeypots/common/` |
| MQTT | Velora Message Gateway | VMG-100 / bounded MQTT 3.1.1 emulation | MQTT / 1883 | No real broker authentication | Bounded MQTT frame assembly and parsing; minimal replies; no persistent broker session | `mqtt.operation`, `packet_type`, `client_id`, `topic`, `packet_id`, `qos`, `flags`, `remaining_length` | `mqtt-recon`, `mqtt-auth-probe` → `MQTT_PROBING` | No delivery, subscriptions, retained messages, persistence, payload execution, or real broker authentication | `sensor/honeypots/mqtt/`, `sensor/honeypots/common/` |

Logstash converts Cowrie-native and custom JSONL records into the canonical schema before Elasticsearch indexing. Credentials above are deliberately synthetic; telemetry containing submitted credentials is research evidence and must remain confined to the lab.

## Persona-aware interaction

Camera reconnaissance probes meaningful protected AsterView endpoints without authenticating, observes their authentication challenges, and records distinct URL interactions for enumeration detection; `camera-default-creds` separately exercises successful authentication. Router reconnaissance uses public Nexora status paths. Credential scenarios submit URL-encoded HTML forms and retain Basic authentication only for compatibility. The VEC-100 scenarios use its defined line commands. MQTT scenarios encode deterministic generic client IDs and broad topic filters. Cowrie enumeration uses one authenticated interactive shell for `hostname`, `uname -a`, `id`, and `cat /etc/os-release`.

Controls (`camera-control`, `router-control`, `iot-control`, `mqtt-control`, and `ssh-control`) stay deliberately low intensity and normally have no expected detection. An attack scenario can legitimately produce secondary detections; its `expected_detection` is the primary evaluation contract.

## Where to read the code

1. `sensor/docker-compose.yml` — fixed sensor services, ports, mounts, health checks, and resource boundaries.
2. `sensor/honeypots/app.py` — explicit dispatcher selecting one custom persona.
3. `sensor/honeypots/common/server.py` — bounded connection handling, HTTP assembly, IoT line reading, MQTT frame reading, and JSONL emission.
4. `sensor/honeypots/{camera,router,iot_service,mqtt}/` and `cowrie/` — protocol parsing, fictional identity, replies, and Cowrie configuration.
5. `sensor/filebeat/filebeat.yml` — edge collection and buffered delivery.
6. `elk/logstash/pipelines/` — normalization, validation, and dead-letter routing.
7. `elk/elasticsearch/index-templates/` — canonical mappings for raw and derived evidence.
8. `backend/app/services/processor.py` and `sessionizer.py` — idempotent processing and source-IP session reconstruction.
9. `backend/app/services/detector.py` — deterministic rules, reasons, and evidence IDs.
10. `backend/app/api/experiments.py` and `evaluation/` — ground truth, metrics, timing, resources, and reports.
11. `frontend/src/lib/api.ts` and `frontend/src/app/` — typed API access and presentation pages.
12. `attacks/runner/run.py` — bounded persona-aware traffic generation and local ground truth.

## Declarative personas (v2)

Decision record: [ADR-0002](../adr/0002-sensor-plugins-and-personas.md). The five
services above now run **inside** persona containers (the single-service
`SERVICE=` containers were removed); each persona container (`PERSONA=<id>`)
runs **several protocol services for one fictional device**, defined in TOML under
`sensor/honeypots/personas/`:

| Persona | Device type | Services (public ports) | Default device |
| --- | --- | --- | --- |
| `dvr-recorder` Hikari HR-16 Network Video Recorder | dvr | telnet 23, web 8101, rtsp 8554 | `host-home` |
| `home-router` Nexora NR-1800 Wireless Router | router | router 8080, web 49152, ssdp 1900/udp, dns 53/udp | `host-home` · Docker |
| `iiot-gateway` Velora VMG-300 IIoT Gateway | iiot_gateway | mqtt 1883, iot-service 9000, modbus 5022, coap 5685/udp | `host-home` · Docker |
| `smart-camera` AsterView CV-210 Network Camera | ip_camera | camera 8081, rtsp 554 | `host-home` · Docker |
| `nas` Strata HomeVault 2 | nas | ftp 2121, web 5000 | `host-office` · Docker |
| `office-printer` Lumen LP-450 Multifunction Printer | printer | snmp 161/udp, web 80, ftp 21 | `host-office` |
| `ops-workstation` Engineering Workstation ENG-WS-03 | workstation | rdp 3389, vnc 5900 | `host-office` |
| `voip-phone` Selva SP-320 IP Phone | voip_phone | sip 5060/udp, tftp 69/udp, web 8099 | `host-office` |
| `edge-server` Edge Analytics Server | server | redis 6379, web 8102 | `host-server` |
| `hmi-panel` Halvern HMI-700 Operator Panel | hmi | vnc 5900, web 8103 | `host-server` |
| `air-handler` Altair AHU-9 Air Handling Unit | building_controller | bacnet 47808/udp, web 8098 | `pi-ot` |
| `building-controller` Corvane BC-40 Building Controller | building_controller | coap 5683/udp, modbus 5021, web 8091 | `pi-ot` · Docker |
| `industrial-plc` Halvern HX-1200 Line Controller | industrial_plc | modbus 502, web 8090, ftp 21 | `pi-ot` · Docker |
| `s7-plc` Kestrel KS-1500 CPU | industrial_plc | s7 102, snmp 161/udp, web 8095 | `pi-ot` |
| `tank-gauge` Petrova TLS-450 Tank Monitor | tank_gauge | atg 10001, web 8096 | `pi-ot` |
| `vfd-drive` Varix VF-700 Variable Frequency Drive | drive | enip 44818, web 8097 | `pi-ot` |

Sixteen personas: six OT (PLCs, tank gauge, drive, air handler, building
controller) and ten IT/IoT. On a fleet, each device runs the personas assigned to
it (default layout `sensor/fleet.toml`; change it in the console under Sensors &
Personas → Fleet; guide: [DEPLOYMENT](../guides/DEPLOYMENT.md)). The single-Pi
Docker mode (`sensor/scripts/start.sh`) runs the six marked "Docker". All vendors,
models and credentials are fictional.

A persona defines identity, `[fingerprint]`, `[credentials] accept = [[user, pass], ...]`
(honey-credentials), `[logging]` (`credentials = "full"|"redact"`, `payload_bytes`),
`[interaction]` bounds, and `[[services]]` with `plugin`, container `port`
(1024 or higher), `public_port` and plugin `options`. One validator
(`sensor/honeypots/common/persona.py`) is used by the sensor and by the backend API.

### Plugin fidelity limits

| Plugin | Implements | Deliberately does not |
| --- | --- | --- |
| `modbus` | FC 1-6, 15, 16, 17, 43/14; exceptions 01/02/03/0B; connection-local write overlay; drifting input registers | persist writes, control any process, implement serial/RTU |
| `coap` | RFC 7252 CON/NON/ACK, `/.well-known/core`, GET/PUT/POST/DELETE codes | block-wise transfer, Observe, DTLS |
| `rtsp` | OPTIONS, DESCRIBE with Basic auth + SDP, SETUP 461, PLAY 455, TEARDOWN | ever send RTP media |
| `ftp` | login (honey-credentials, optional anonymous), navigation replies, 3-strike close | open any data connection (no bounce, no file drop) |
| `ssdp` | M-SEARCH responses pointing at the persona's description document | NOTIFY announcements, eventing |
| `dns` | authoritative A/TXT answers for the persona zone, CHAOS version.bind | recursion, ANY, zone transfer |
| `http-device` | configurable pages, Basic/form login, expiring session cookies | server-side logic beyond templating |
| `s7comm` | COTP connect, setup communication, SZL 0x0011 identity read, read/write var, download, PLC stop (refused under `read_only`) | run a program, keep state across connections |
| `bacnet` | Who-Is → I-Am, ReadProperty (object/model/vendor name), WriteProperty (error under `read_only`) | segmentation, COV subscriptions, BBMD |
| `enip` | ListIdentity, ListServices, RegisterSession, SendRRData CIP get/set (status 0x0F under `read_only`) | connected (Class 1) I/O, real CIP object model |
| `atg` | TLS-350 style `I20100` inventory and `S6xx` set commands (9999 under `read_only`) | the full command set, alarms |
| `telnet` | IAC negotiation, BusyBox login, honey-credentials, lockout, emulated shell replies | execute anything; `wget`/`tftp` never fetch |
| `snmp` | v1/v2c GET/GET-NEXT on the system MIB, default communities, SET (refused under `read_only`/`deny_auth`) | v3, walking a real MIB tree |
| `redis` | RESP; PING/INFO/KEYS/GET; CONFIG SET/SLAVEOF/MODULE flagged as exploits and acknowledged, never applied | persist keys, replicate, load modules |
| `sip` | OPTIONS/REGISTER/INVITE replies (401 for known extensions, 404 otherwise), scanner user-agent capture | calls, RTP |
| `tftp` | RRQ/WRQ parsed and logged; always answered with an error | transfer any file |
| `vnc` | RFB 3.8 handshake, VNC auth challenge; authentication always fails | a framebuffer session |
| `rdp` | X.224 connection request with `mstshash` cookie user capture; negotiation refused | TLS/CredSSP, a desktop |

### Managing personas

`GET /personas` lists effective personas with deployment drift (derived from
heartbeats). `PUT /personas/{id}` (admin) validates and stores a new immutable
version; `POST /personas/{id}/state` enables or disables one. Sensors with
`PERSONA_FROM_BACKEND=true` load the active version at start and fall back to the
baked-in file. Deploy with `docker compose restart <container>` on the Pi (or the console's restart action through the SSH whitelist).
