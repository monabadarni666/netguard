from collections import defaultdict
from datetime import datetime
import time

from scapy.all import sniff, IP, TCP, UDP


INTERFACE = "en0"

flows = defaultdict(
    lambda: {
        "start_time": None,
        "last_time": None,
        "packets": 0,
        "bytes": 0,
        "protocol": None,
    }
)


def get_protocol(packet):
    if TCP in packet:
        return "tcp"

    if UDP in packet:
        return "udp"

    return "other"


def get_ports(packet):
    if TCP in packet:
        return packet[TCP].sport, packet[TCP].dport

    if UDP in packet:
        return packet[UDP].sport, packet[UDP].dport

    return 0, 0


def process_packet(packet):
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    src_port, dst_port = get_ports(packet)

    protocol = get_protocol(packet)

    flow_key = (
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
    )

    now = time.time()

    flow = flows[flow_key]

    if flow["start_time"] is None:
        flow["start_time"] = now

    flow["last_time"] = now
    flow["packets"] += 1
    flow["bytes"] += len(packet)
    flow["protocol"] = protocol

    duration = (
        flow["last_time"]
        - flow["start_time"]
    )

    print(
        f"{datetime.now().strftime('%H:%M:%S')} | "
        f"{src_ip}:{src_port} -> "
        f"{dst_ip}:{dst_port} | "
        f"{protocol.upper():<5} | "
        f"Packets: {flow['packets']:<4} | "
        f"Bytes: {flow['bytes']:<7} | "
        f"Duration: {duration:.2f}s"
    )


def main():
    print("=" * 80)
    print("AI CYBERSECURITY PLATFORM")
    print("LIVE NETWORK COLLECTOR")
    print("=" * 80)

    print(f"\nListening on interface: {INTERFACE}")
    print("Press CTRL+C to stop.\n")

    try:
        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False,
        )

    except KeyboardInterrupt:
        print("\nCollector stopped.")


if __name__ == "__main__":
    main()
