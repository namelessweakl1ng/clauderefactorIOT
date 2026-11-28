# Attack scenarios

67 bounded, single-target scenarios in `attacks/scenarios/` (55 attacks, 12 controls,
covering 25 services). Run one with

```bash
python -m attacks.runner.run <id> --target <sensor-ip>                 # LAB_SUBNET must contain the target
python -m attacks.runner.run <id> --target <ip> --experiment-id EXP-... --api-url http://<analysis>:8000
```

The runner validates the target against `LAB_SUBNET`, talks to exactly one host,
caps each step at 64 requests and each pause at 120 s, and never scans, persists
or transfers real payloads (dropper URLs use the unroutable TEST-NET-2 range; TFTP
and FTP transfers are refused by the decoys; Redis writes are acknowledged and
discarded).

**Tested end to end.** `tests/safety/test_scenarios_against_personas.py` executes
every scenario that targets persona services through the real runner against
the real persona runtime, normalizer and detector: each attack must produce its
`expected_detection` and each control must produce no detection. Scenarios that
need the Cowrie container (`ssh`, `telnet`) or the legacy device containers are
exercised in the lab only. `evaluation/measure_hardening.py` runs every in-process
attack under each RL hardening action to measure what the action changes.

Services: `iot-telnet` is the BusyBox telnet shell of embedded personas (DVR);
`telnet` is Cowrie's. ICS: `modbus`, `s7`, `bacnet`, `enip`, `atg` (tank gauge),
`coap`. IT: `snmp`, `redis`, `sip`, `tftp`, `vnc`, `rdp`, `rtsp`, `ftp`, `dns`,
`ssdp`, `web`.

Step options (beyond `service`): `port`, `paths` (HTTP enumeration),
`credentials` + `attempt_interval` (SSH / telnet credential lists), `commands`
(shell lines; Redis argument lists; ATG command codes), `operation`/`topic`/`message`
(MQTT), `requests`/`sweep` (Modbus, CoAP, SNMP), `operations` (S7, EtherNet/IP),
`services` (BACnet), `community`/`communities` (SNMP), `method`/`extensions`/`user_agent`
(SIP), `operation`/`files` (TFTP), `attempts` (VNC), `usernames` (RDP),
`method`/`paths`/`username`/`password` (RTSP), `queries` (DNS),
`search_targets` (SSDP), `pause_before` (low-and-slow pacing).

| Scenario | Kind | Expected detection | Services | Models (ATT&CK) | What it does |
| --- | --- | --- | --- | --- | --- |
| `atg-inventory-recon` | attack | ICS_RECONNAISSANCE | atg | T0888 | The TLS-350 I20100 in-tank inventory command, the single most common probe seen by GasPot-style ATG honeypots. |
| `atg-tank-relabel` | attack | ICS_WRITE | atg | T0888 -> T0836 | Inventory read, then S602 tank-label change: the defacement attack repeatedly observed against exposed tank gauges. |
| `bacnet-device-discovery` | attack | ICS_RECONNAISSANCE | bacnet | T0846 -> T0888 | Who-Is, then ReadProperty object-name and model-name: the BACnet discovery used by Nmap bacnet-info and Shodan. |
| `bacnet-setpoint-override` | attack | ICS_WRITE | bacnet | T0846 -> T0836 | Discover the air handler, then WriteProperty a present-value at priority 8: an unauthorised HVAC setpoint change. |
| `building-actuator-tamper` | attack | UNAUTHORIZED_COMMAND | coap | T0855, T0836 | Discovers actuators, forces the damper fully open, raises the setpoint and deletes a resource. |
| `building-coap-discovery` | attack | RECONNAISSANCE | coap | T1046, T0888 | Lists resources via /.well-known/core and reads each sensor, as CoAP scanners do. |
| `camera-default-creds` | attack | DEFAULT_CREDENTIALS | camera | — | Submit one known synthetic camera credential |
| `camera-recon` | attack | WEB_ENUMERATION | camera | — | Probe AsterView endpoints and authentication boundaries |
| `camera-rtsp-default-creds` | attack | DEFAULT_CREDENTIALS | rtsp | T1078.001 | Finds the stream with OPTIONS, then DESCRIBE with the vendor default admin/admin, which the persona accepts. |
| `camera-stream-hunt` | attack | RECONNAISSANCE | rtsp | T1595.003 | Unauthenticated DESCRIBE across nine vendor stream paths, as camera-hunting tools do before guessing credentials. |
| `cross-service-recon` | attack | MULTI_SERVICE_ACTIVITY | camera, router, mqtt | — | Fingerprint AsterView and Nexora endpoints, then inspect MQTT topics |
| `dvr-telnet-default-login` | attack | DEFAULT_CREDENTIALS | iot-telnet | — | One login with the vendor's documented default credentials, then device identification commands. |
| `dvr-telnet-mirai-dropper` | attack | MALWARE_DOWNLOAD | iot-telnet | T1110.001 -> T1059.004 -> T1105 | Mirai's credential table against the DVR's BusyBox telnet until admin/admin works, the ECCHI applet probe, a CPU check, then a wget/tftp dropper fetch from a TEST-NET address. The shell never fetches anything. |
| `enip-drive-parameter-write` | attack | ICS_WRITE | enip | T0846 -> T0836 | Register a session and send an unconnected CIP Set_Attribute_Single: changing a drive parameter with no authentication. |
| `enip-identity-scan` | attack | ICS_RECONNAISSANCE | enip | T0846 | One ListIdentity encapsulation command: what enip-info / pyenip / Shodan send to fingerprint a drive or PLC. |
| `ftp-low-and-slow` | attack | BRUTE_FORCE | ftp | T1110.001 | Six failed logins spaced 50 seconds apart, designed to stay under naive per-minute thresholds. |
| `gateway-mqtt-command-injection` | attack | UNAUTHORIZED_COMMAND | mqtt | T0861 -> T0855 | Connects anonymously, subscribes to the '#' wildcard, then publishes an 'off' command to an HVAC set topic. |
| `http-enumeration` | attack | WEB_ENUMERATION | http | — | Request distinct administrative paths |
| `ics-hmi-to-plc-campaign` | attack | MULTI_STAGE_ATTACK | web, modbus | T0812 -> T0855 | Logs into the PLC's web HMI with default credentials, then issues a Modbus register write, crossing from IT-style access to process impact. |
| `ics-modbus-recon` | attack | ICS_RECONNAISSANCE | modbus | T0888, T0861 | Read Device Identification and Report Server ID, then sweep holding and input registers to map process points. |
| `ics-setpoint-tamper` | attack | ICS_WRITE | modbus | T0855, T0836 | Reads the oven setpoint, overwrites it with an unsafe value, writes a block of registers and reads back to verify, the pattern of process-manipulation malware. |
| `iot-default-creds` | attack | DEFAULT_CREDENTIALS | iot | — | Submit one bounded VEC-100 AUTH command |
| `iot-exploit-sweep` | attack | EXPLOIT_ATTEMPT | router | T1190, T1595.002 | Requests the URL paths of well-known router/camera exploits (HNAP, GPON, Boa, LuCI, Netgear setup.cgi, path traversal, exposed secrets) against the router UI. |
| `iot-fleet-sweep` | attack | MULTI_SERVICE_ACTIVITY | modbus, coap, rtsp, ftp, dns, web | T1046 | One light touch on each of six device services (Modbus, CoAP, RTSP, FTP, DNS, web) within two minutes, the footprint of a horizontal IoT scanner. |
| `iot-probe` | attack | RECONNAISSANCE | iot | — | Three bounded device commands |
| `mirai-style-infection` | attack | MALWARE_DOWNLOAD | ssh | T1110.001 -> T1059.004 -> T1105 | Credential list from Mirai's table until root/root works, BusyBox applet probe, CPU fingerprint, then a dropper fetch from an unroutable TEST-NET address and chmod in /tmp. Cowrie emulates every command. |
| `mqtt-auth-probe` | attack | MQTT_PROBING | mqtt | — | Bounded MQTT CONNECT probes |
| `mqtt-recon` | attack | MQTT_PROBING | mqtt | — | MQTT CONNECT, SUBSCRIBE and PING packets |
| `multi-honeypot-attack` | attack | MULTI_STAGE_ATTACK | ssh, telnet, camera, iot, mqtt, router | — | Deterministic bounded interaction across all six logical services |
| `multi-stage` | attack | MULTI_STAGE_ATTACK | ssh, camera, iot | — | Failed gateway authentication followed by camera and controller reconnaissance |
| `nas-anonymous-ftp-exfil` | attack | DEFAULT_CREDENTIALS | ftp | T1078.001, T1105 | Logs in anonymously, browses the backup share, tries to download an archive and stage a file. The decoy refuses every data transfer. |
| `ot-network-campaign` | attack | ICS_WRITE | snmp, rdp, s7 | T1595 -> T0886 -> T0888 -> T0816 | SNMP sweep of the printer, an RDP probe of the engineering workstation, then S7 identification and a PLC stop: one attacker crossing from IT services into the controller. |
| `plc-firmware-implant` | attack | MALWARE_DOWNLOAD | ftp | T1105, T0839 | Uses the PLC's default FTP credentials to upload a modified firmware image (refused at the data channel). |
| `rdp-username-probe` | attack | RECONNAISSANCE | rdp | T1595 -> T1110 | X.224 connection requests carrying mstshash cookies for common admin names, as RDP brute-forcers send before NLA. |
| `redis-rogue-master` | attack | EXPLOIT_ATTEMPT | redis | T1190 -> T1105 | SLAVEOF a TEST-NET 'rogue master' and MODULE LOAD a shared object: the P2PInfect / H2Miner replication RCE chain. |
| `redis-ssh-key-implant` | attack | EXPLOIT_ATTEMPT | redis | T1190 -> T1098.004 | INFO, then CONFIG SET dir/dbfilename to /root/.ssh/authorized_keys, SET a key and SAVE: the classic unauthenticated Redis-to-SSH technique. The decoy acknowledges and writes nothing. |
| `router-default-creds` | attack | DEFAULT_CREDENTIALS | router | — | Submit one known synthetic router credential |
| `router-dns-fingerprint` | attack | RECONNAISSANCE | dns | T1595.002 | CHAOS version.bind, an ANY amplification test, and lookups of likely internal names. |
| `router-recon` | attack | WEB_ENUMERATION | router | — | Inspect bounded router paths |
| `router-upnp-discovery` | attack | RECONNAISSANCE | ssdp, web | T1046 | M-SEARCH for all devices, root devices and Internet Gateway Devices, then fetches the advertised description document. |
| `s7-logic-download` | attack | ICS_WRITE | s7 | T0843 -> T0836 | Request-download then a variable write: the pattern of a logic implant pushed to the controller. |
| `s7-plc-enumeration` | attack | ICS_RECONNAISSANCE | s7 | T0846 -> T0888 | ISO-on-TCP connect, S7 setup, then an SZL 0x0011 module-identification read, as done by s7-info / Nmap s7-info.nse and the Conpot S7 template probes. |
| `s7-plc-stop` | attack | ICS_WRITE | s7 | T0888 -> T0816 | Identify the CPU, then issue PLC STOP: the loss-of-control step from Stuxnet-era and PLC-Blaster-style tooling. |
| `sip-extension-enumeration` | attack | RECONNAISSANCE | sip | T1087 | REGISTER for ten consecutive extensions (svwar): 401 vs 404 reveals which ones exist. |
| `sip-scanner-sweep` | attack | RECONNAISSANCE | sip | T1595 | OPTIONS with the friendly-scanner user agent: the svmap fingerprint that dominates SIP honeypot traffic. |
| `snmp-community-guessing` | attack | BRUTE_FORCE | snmp | T1110.001 | A short onesixtyone-style list of common communities, one sysDescr GET each. |
| `snmp-default-community` | attack | DEFAULT_CREDENTIALS | snmp | — | One GET of sysDescr with community 'public', as onesixtyone, snmp-check and every IoT scanner do first. |
| `snmp-printer-reconfigure` | attack | UNAUTHORIZED_COMMAND | snmp | T1078.001 -> T1565 | Read sysDescr, then SET sysContact with 'private': unauthorised reconfiguration over a default write community. |
| `ssh-bruteforce` | attack | BRUTE_FORCE | ssh | — | Six failed SSH password authentications |
| `ssh-credential-spray` | attack | BRUTE_FORCE | ssh | T1110.003 | Twelve distinct username/password pairs from public IoT default lists, one attempt each, no success. |
| `ssh-interaction` | attack | COMMAND_INTERACTION | ssh | — | One Cowrie login with harmless first-stage device enumeration |
| `telnet-auth-attempts` | attack | BRUTE_FORCE | telnet | — | Bounded Telnet input attempts |
| `tftp-implant-upload` | attack | MALWARE_DOWNLOAD | tftp | T1105 | TFTP WRQ of a binary: the push-style infection used by IoT botnets on devices with TFTP servers. Always refused. |
| `tftp-phone-config-theft` | attack | RECONNAISSANCE | tftp | T1552.001 | TFTP RRQ for the phone's provisioning files, which on real phones hold SIP passwords. |
| `vnc-password-guessing` | attack | BRUTE_FORCE | vnc | T1110.001 | Six RFB 3.8 VNC-authentication attempts against the HMI panel. |
| `building-coap-control` | control | — | coap | — | One GET of a temperature resource. |
| `camera-control` | control | — | camera | — | One ordinary camera root request |
| `camera-rtsp-control` | control | — | rtsp | — | A single capability query, like a legitimate player's first request. |
| `enip-hmi-session-control` | control | — | enip | — | Register a session and read attributes, as a supervisory HMI does. |
| `ftp-control` | control | — | ftp | — | One mistyped password. |
| `ics-modbus-control` | control | — | modbus | — | One HMI-style read of two holding registers. |
| `iot-control` | control | — | iot | — | One bounded ordinary status request |
| `mqtt-control` | control | — | mqtt | — | One ordinary MQTT CONNECT control |
| `redis-cache-read-control` | control | — | redis | — | PING and two GETs, as the analytics service on the edge server does. |
| `router-control` | control | — | router | — | One ordinary router root request |
| `s7-hmi-poll-control` | control | — | s7 | — | Connect, set up communication and read one variable, as an HMI does every cycle. |
| `ssh-control` | control | — | ssh | — | One non-default credential authentication attempt |
