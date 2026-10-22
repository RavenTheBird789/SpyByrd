#!/usr/bin/env python3
import argparse
import asyncio
import csv
import sys
import time
import threading
from datetime import datetime

def green(text: str) -> str:
    return f"\033[92m{text}\033[0m"

def red(text: str) -> str:
    return f"\033[91m{text}\033[0m"

def yellow(text: str) -> str:
    return f"\033[93m{text}\033[0m"

def purple(text: str) -> str:
    return f"\033[35m{text}\033[0m"

try:
    from bleak import BleakScanner
except ImportError:
    BleakScanner = None

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
except ImportError:
    sniff = None


class DeviceStore:
    """Thread-safe store of discovered devices, deduped by id."""
    def __init__(self):
        self._lock = threading.Lock()
        self._devices = {}

    def add(self, key, record):
        with self._lock:
            existing = self._devices.get(key)
            if existing:
                existing["last_seen"] = record["last_seen"]
                existing["count"] = existing.get("count", 1) + 1
                if record.get("rssi") is not None:
                    existing["rssi"] = record["rssi"]
            else:
                record["count"] = 1
                self._devices[key] = record
                self._print_new(record)

    def _print_new(self, r):
        ts = r["last_seen"].strftime("%H:%M:%S")
        rssi = r.get("rssi")
        rssi = "?" if rssi is None else rssi
        print(purple(f"[{ts}] [{r['type']:^5}] {r.get('addr',''):18} "
                     f"RSSI={rssi:>5} {r.get('name','')}"))

    def snapshot(self):
        with self._lock:
            return list(self._devices.values())

store = DeviceStore()

async def ble_scan(duration, interface=None):
    if BleakScanner is None:
        print(red("[!] bleak not installed. Skipping BLE scan (pip install bleak)"))
        return

    def callback(device, adv_data):
        record = {
            "type": "BLE",
            "addr": device.address,
            "name": device.name or (adv_data.local_name if adv_data else "") or "",
            "rssi": adv_data.rssi if adv_data else device.rssi,
            "last_seen": datetime.now(),
        }
        store.add(f"BLE-{device.address}", record)

    kwargs = {}
    if interface:
        kwargs["adapter"] = interface

    scanner = BleakScanner(detection_callback=callback, **kwargs)
    await scanner.start()
    try:
        await asyncio.sleep(duration)
    finally:
        await scanner.stop()


def run_ble_scan(duration, interface=None):
    asyncio.run(ble_scan(duration, interface))

def wifi_packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]

    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        bssid = dot11.addr2
        if not bssid:
            return

        ssid = None
        channel = None
        crypto = set()

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode(errors="replace")
                except Exception:
                    ssid = "<hidden>"
            elif elt.ID == 3:
                try:
                    channel = ord(elt.info)
                except Exception:
                    pass
            elt = elt.payload.getlayer(Dot11Elt)

        cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                           "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        if "privacy" in cap.lower():
            crypto.add("WEP/WPA")

        try:
            rssi = pkt.dBm_AntSignal
        except Exception:
            rssi = None

        record = {
            "type": "WIFI",
            "addr": bssid,
            "name": ssid or "<hidden>",
            "rssi": rssi,
            "channel": channel,
            "last_seen": datetime.now(),
        }
        store.add(f"WIFI-{bssid}", record)


def run_wifi_scan(duration, interface):
    if sniff is None:
        print(red("[!] scapy not installed. Skipping WiFi scan (pip install scapy)"))
        return
    if not interface:
        print(red("[!] No WiFi monitor-mode interface given. Skipping WiFi scan"))
        return

    print(purple(f"[*] Sniffing WiFi beacons on {interface} (monitor mode assumed)..."))
    try:
        sniff(iface=interface, prn=wifi_packet_handler, timeout=duration, store=False)
    except PermissionError:
        print(red("[!] Permission denied — run as root/with CAP_NET_RAW for WiFi sniffing."))
    except OSError as e:
        print(red(f"[!] WiFi sniff error: {e} ") +
              yellow(f"(is {interface} really in monitor mode?)"))

def export_csv(path):
    rows = store.snapshot()
    if not rows:
        print(red("[!] No devices found, nothing to export."))
        return
    fieldnames = ["type", "addr", "name", "rssi", "channel", "count", "last_seen"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            r = dict(r)
            r["last_seen"] = r["last_seen"].isoformat()
            writer.writerow(r)
    print(green(f"[*] Exported {len(rows)} devices to {path}"))

def trademark(main_func):
    def wrapper():
        print(purple("        ___  "))
        print(purple("       |*>*| "))
        print(purple("      |  U  |"))
        print(purple("        - -  "))
        print(purple("-" * 19))
        print(purple((" " * 6) + "SpyByrd"))
        print(purple("-" * 19))
        print(red("By: RavenTheBird789\n"))
        main_func();
    return wrapper

@trademark
def main():
    ap = argparse.ArgumentParser(description="BLE + WiFi scanner")
    ap.add_argument("-d", "--duration", type=int, default=30,
                     help="Scan duration in seconds (default: 30)")
    ap.add_argument("--wifi-iface", help="WiFi interface in monitor mode (e.g. wlan0mon)")
    ap.add_argument("--ble-iface", help="BLE adapter (Linux hci id, e.g. hci0)")
    ap.add_argument("--no-ble", action="store_true", help="Disable BLE scanning")
    ap.add_argument("--no-wifi", action="store_true", help="Disable WiFi scanning")
    ap.add_argument("-o", "--output", help="Export results to CSV file")
    args = ap.parse_args()

    threads = []

    if not args.no_wifi:
        t = threading.Thread(target=run_wifi_scan,
                              args=(args.duration, args.wifi_iface),
                              daemon=True)
        threads.append(t)

    if not args.no_ble:
        t = threading.Thread(target=run_ble_scan,
                              args=(args.duration, args.ble_iface),
                              daemon=True)
        threads.append(t)

    if not threads:
        print(red("Both BLE and WiFi scanning disabled — nothing to do."))
        sys.exit(1)

    print(green(f"[*] Starting scan for {args.duration}s (Ctrl+C to stop early)...\n"))
    for t in threads:
        t.start()
    try:
        deadline = time.monotonic() + args.duration + 5
        while any(t.is_alive() for t in threads) and time.monotonic() < deadline:
            for t in threads:
                t.join(0.2)
    except KeyboardInterrupt:
        print(yellow("\n[!] Interrupted. Stopping scan and keeping results so far..."))

    devices = store.snapshot()
    print(green(f"\n[*] Scan complete. {len(devices)} unique devices found."))

    if args.output:
        export_csv(args.output)

if __name__ == "__main__":
    main()