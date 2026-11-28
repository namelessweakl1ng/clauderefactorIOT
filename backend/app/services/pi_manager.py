import asyncio

from ..config import get_settings

MANAGE_SCRIPT = "/opt/trapsig/sensor/scripts/manage.sh"
HONEYPOTS = {
    "cowrie": {"name": "Cowrie SSH/Telnet", "protocol": "ssh/telnet", "port": "2222/2223", "description": "Emulated shell for credential and command capture"},
    "camera": {
        "persona": "smart-camera",
        "name": "AsterView CV-210 camera",
        "protocol": "http/rtsp",
        "port": "8081/554",
        "description": "Camera web UI and RTSP control plane",
    },
    "router": {
        "persona": "home-router",
        "name": "Nexora NR-1800 router",
        "protocol": "http/ssdp/dns",
        "port": "8080/1900/53",
        "description": "Router admin, UPnP discovery, authoritative-only DNS",
    },
    "gateway": {
        "persona": "iiot-gateway",
        "name": "Velora VMG-300 IIoT gateway",
        "protocol": "mqtt/vcp/modbus/coap",
        "port": "1883/9000/5022/5685",
        "description": "MQTT broker, VCP controller, Modbus map, CoAP telemetry",
    },
    "plc": {
        "persona": "industrial-plc",
        "name": "Halvern HX-1200 PLC",
        "protocol": "modbus/http/ftp",
        "port": "502/8090/21",
        "description": "Packaging-line PLC with HMI and firmware FTP",
    },
    "building": {
        "persona": "building-controller",
        "name": "Corvane BC-40 building controller",
        "protocol": "coap/modbus/http",
        "port": "5683/5021/8091",
        "description": "HVAC controller with CoAP actuators",
    },
    "nas": {"persona": "nas", "name": "Strata HomeVault 2 NAS", "protocol": "ftp/http", "port": "2121/5000", "description": "Home NAS with anonymous FTP"},
}


class PiManager:
    async def _ssh(self, *arguments: str) -> str:
        cfg = get_settings()
        if not cfg.pi_host:
            raise RuntimeError("PI_HOST is not configured")
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            "-i",
            cfg.pi_ssh_key,
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={cfg.pi_known_hosts}",
            "-o",
            "ConnectTimeout=5",
            f"{cfg.pi_user}@{cfg.pi_host}",
            MANAGE_SCRIPT,
            *arguments,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        if proc.returncode:
            raise RuntimeError(err.decode().strip() or "Pi action failed")
        return out.decode().strip()

    async def action(self, honeypot_id: str, action: str) -> dict:
        if honeypot_id not in HONEYPOTS:
            raise ValueError("unknown honeypot")
        if action not in {"start", "stop", "restart"}:
            raise ValueError("unsupported action")
        output = await self._ssh(action, honeypot_id)
        return {"honeypot_id": honeypot_id, "action": action, "output": output}

    async def statuses(self) -> dict[str, str]:
        try:
            lines = (await self._ssh("status")).splitlines()
            parsed = dict(line.split("=", 1) for line in lines if "=" in line)
            return {name: parsed.get(name, "stopped") for name in HONEYPOTS}
        except RuntimeError:
            return {name: "unreachable" for name in HONEYPOTS}


pi_manager = PiManager()
