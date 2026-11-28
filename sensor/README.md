# sensor/: what runs on the honeypot devices

Everything an attacker touches. It is pure-Python, standard-library-only
emulation: nothing executes attacker input.

```
sensor/
├── fleet.toml                      default layout: which personas run on which device
├── trapsig-sensor.example.toml     per-device agent config (copy, set sensor_id)
├── honeypots/
│   ├── agent.py        the fleet agent for Pi OS Lite, Linux and Windows (start here)
│   ├── personas/       16 device personas, one TOML each (PLC, DVR, printer, ...)
│   ├── plugins/        protocol emulators: modbus, ics (S7/BACnet/CIP/ATG), services
│   │                   (telnet/SNMP/Redis/SIP/TFTP/VNC/RDP), coap, rtsp, ftp, dns, ssdp, http_device
│   ├── common/         runtime (servers, limits, telemetry), persona loader, hardening
│   │                   enforcement, heartbeats, plugin base class
│   ├── camera/ router/ iot_service/ mqtt/   legacy device apps used by the Docker mode
│   ├── cowrie/         SSH/Telnet honeypot config (Docker mode only)
│   └── app.py, Dockerfile, healthcheck.py   container entry point (Docker mode)
├── docker-compose.yml, .env.example, filebeat/, scripts/   single-device Docker mode (Pi)
```

**Two ways to run it:**

* **Fleet agent (recommended; several devices).** Run one `agent.py` per device.
  It pulls its assignment from the backend, hot-reloads personas, and ships events
  to Logstash over HTTP. Guide: [DEPLOYMENT](../docs/guides/DEPLOYMENT.md).

  ```bash
  python3 honeypots/agent.py check --config trapsig-sensor.toml     # validate + test every port
  python3 honeypots/agent.py run   --config trapsig-sensor.toml
  ```

* **Docker on one Pi.** Runs `scripts/setup.sh`, then `scripts/start.sh`
  (Cowrie, the six original personas and Filebeat). Guide:
  [SETUP](../docs/guides/SETUP.md).

Persona format and how to add one: [PERSONAS](../docs/reference/PERSONAS.md).
