"""Importing this package registers every protocol plugin."""

from plugins import coap, dns, ftp, http_device, ics, legacy, modbus, rtsp, services, ssdp  # noqa: F401

__all__ = ["coap", "dns", "ftp", "http_device", "ics", "legacy", "modbus", "rtsp", "services", "ssdp"]
