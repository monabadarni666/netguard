import csv
import time
from datetime import datetime
from pathlib import Path

import requests

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    get_if_addr,
)


# ==========================================================
# Configuration
# ==========================================================

INTERFACE = "en0"

FLOW_TIMEOUT = 15

API_URL = "http://127.0.0.1:8000/predict/live"

LOCAL_IP = get_if_addr(INTERFACE)


BASE_DIR = Path(__file__).resolve().parent.parent

LIVE_DATA_PATH = (
    BASE_DIR
    / "ml"
    / "data"
    / "live_flows.csv"
)


flows = {}


# ==========================================================
# Packet helpers
# ==========================================================

def get_protocol(packet):

    if TCP in packet:
        return "tcp"

    if UDP in packet:
        return "udp"

    return "other"


def get_ports(packet):

    if TCP in packet:
        return (
            packet[TCP].sport,
            packet[TCP].dport
        )

    if UDP in packet:
        return (
            packet[UDP].sport,
            packet[UDP].dport
        )

    return 0, 0


# ==========================================================
# Bidirectional flow key
# ==========================================================

def canonical_flow_key(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol
):

    endpoint_a = (
        src_ip,
        src_port
    )

    endpoint_b = (
        dst_ip,
        dst_port
    )

    if endpoint_a <= endpoint_b:

        return (
            endpoint_a,
            endpoint_b,
            protocol
        )

    return (
        endpoint_b,
        endpoint_a,
        protocol
    )


# ==========================================================
# Create Flow
# ==========================================================

def create_flow(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol,
    timestamp
):

    return {

        "src_ip": src_ip,
        "dst_ip": dst_ip,

        "src_port": src_port,
        "dst_port": dst_port,

        "protocol": protocol,

        "start_time": timestamp,
        "last_time": timestamp,

        "spkts": 0,
        "dpkts": 0,

        "sbytes": 0,
        "dbytes": 0,

        "source_packet_times": [],
        "destination_packet_times": [],

        "source_packet_sizes": [],
        "destination_packet_sizes": [],
    }


# ==========================================================
# Update Flow
# ==========================================================

def update_flow(packet):

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    src_port, dst_port = get_ports(
        packet
    )

    protocol = get_protocol(
        packet
    )

    now = time.time()


    key = canonical_flow_key(
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol
    )


    if key not in flows:

        flows[key] = create_flow(
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            now
        )


    flow = flows[key]

    flow["last_time"] = now

    packet_size = len(packet)


    if (
        src_ip == flow["src_ip"]
        and
        src_port == flow["src_port"]
    ):

        flow["spkts"] += 1

        flow["sbytes"] += packet_size

        flow[
            "source_packet_times"
        ].append(now)

        flow[
            "source_packet_sizes"
        ].append(packet_size)

    else:

        flow["dpkts"] += 1

        flow["dbytes"] += packet_size

        flow[
            "destination_packet_times"
        ].append(now)

        flow[
            "destination_packet_sizes"
        ].append(packet_size)


# ==========================================================
# Feature calculations
# ==========================================================

def mean(values):

    if not values:
        return 0.0

    return (
        sum(values)
        / len(values)
    )


def average_interval_ms(times):

    if len(times) < 2:
        return 0.0

    intervals = [

        times[i]
        -
        times[i - 1]

        for i
        in range(
            1,
            len(times)
        )
    ]

    average_seconds = (
        sum(intervals)
        / len(intervals)
    )

    return (
        average_seconds
        * 1000.0
    )


# ==========================================================
# Extract ML Features
# ==========================================================

def extract_features(flow):

    duration = (
        flow["last_time"]
        -
        flow["start_time"]
    )


    safe_duration = max(
        duration,
        0.000001
    )


    total_packets = (
        flow["spkts"]
        +
        flow["dpkts"]
    )


    rate = (
        total_packets
        /
        safe_duration
    )


    rate = min(
        rate,
        1_000_000.0
    )


    return {

        "dur": float(duration),

        "proto":
            flow["protocol"],

        "spkts":
            int(flow["spkts"]),

        "dpkts":
            int(flow["dpkts"]),

        "sbytes":
            int(flow["sbytes"]),

        "dbytes":
            int(flow["dbytes"]),

        "rate":
            float(rate),

        "sinpkt":
            float(
                average_interval_ms(
                    flow[
                        "source_packet_times"
                    ]
                )
            ),

        "dinpkt":
            float(
                average_interval_ms(
                    flow[
                        "destination_packet_times"
                    ]
                )
            ),

        "smean":
            float(
                mean(
                    flow[
                        "source_packet_sizes"
                    ]
                )
            ),

        "dmean":
            float(
                mean(
                    flow[
                        "destination_packet_sizes"
                    ]
                )
            ),
    }


# ==========================================================
# Flow filtering
# ==========================================================

def should_analyze_flow(features):

    total_packets = (
        features["spkts"]
        +
        features["dpkts"]
    )


    if features["proto"] not in {
        "tcp",
        "udp"
    }:

        return (
            False,
            "unsupported protocol"
        )


    if total_packets < 3:

        return (
            False,
            "too few packets"
        )


    if features["dur"] < 0.01:

        return (
            False,
            "flow duration too short"
        )


    return (
        True,
        None
    )


# ==========================================================
# Send to AI
# ==========================================================

def send_to_ai(features):

    try:

        response = requests.post(
            API_URL,
            json=features,
            timeout=10
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:

        print()
        print(
            "Could not send flow "
            "to AI backend:"
        )

        print(error)

        return None


# ==========================================================
# Save Live Flow to CSV
# ==========================================================

def save_live_flow(
    flow,
    features,
    result
):

    file_exists = (
        LIVE_DATA_PATH.exists()
        and
        LIVE_DATA_PATH.stat().st_size > 0
    )


    fieldnames = [

        "timestamp",

        "src_ip",
        "dst_ip",

        "src_port",
        "dst_port",

        "dur",
        "proto",

        "spkts",
        "dpkts",

        "sbytes",
        "dbytes",

        "rate",

        "sinpkt",
        "dinpkt",

        "smean",
        "dmean",

        "prediction",
        "risk_score",
        "severity",
        "attack_probability",
    ]


    row = {

        "timestamp":
            datetime.now().isoformat(),

        "src_ip":
            flow["src_ip"],

        "dst_ip":
            flow["dst_ip"],

        "src_port":
            flow["src_port"],

        "dst_port":
            flow["dst_port"],

        "dur":
            features["dur"],

        "proto":
            features["proto"],

        "spkts":
            features["spkts"],

        "dpkts":
            features["dpkts"],

        "sbytes":
            features["sbytes"],

        "dbytes":
            features["dbytes"],

        "rate":
            features["rate"],

        "sinpkt":
            features["sinpkt"],

        "dinpkt":
            features["dinpkt"],

        "smean":
            features["smean"],

        "dmean":
            features["dmean"],

        "prediction":
            result["prediction"],

        "risk_score":
            result["risk_score"],

        "severity":
            result["severity"],

        "attack_probability":
            result[
                "attack_probability"
            ],
    }


    with open(
        LIVE_DATA_PATH,
        "a",
        newline=""
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames
        )


        if not file_exists:

            writer.writeheader()


        writer.writerow(
            row
        )


# ==========================================================
# Process completed Flow
# ==========================================================

def process_completed_flow(flow):

    features = extract_features(
        flow
    )


    analyze, reason = should_analyze_flow(
        features
    )


    if not analyze:

        print()
        print("=" * 76)

        print(
            f"SKIPPED FLOW: "
            f"{flow['src_ip']}:{flow['src_port']} "
            f"<-> "
            f"{flow['dst_ip']}:{flow['dst_port']}"
        )

        print(
            f"Reason: {reason}"
        )

        return


    print()
    print("=" * 76)


    print(
        f"FLOW: "
        f"{flow['src_ip']}:{flow['src_port']} "
        f"<-> "
        f"{flow['dst_ip']}:{flow['dst_port']}"
    )


    print(
        f"Protocol: "
        f"{features['proto'].upper()}"
    )


    print(
        f"Duration: "
        f"{features['dur']:.3f}s"
    )


    print(
        f"Packets: "
        f"{features['spkts']} -> "
        f"{features['dpkts']}"
    )


    print(
        f"Bytes: "
        f"{features['sbytes']} -> "
        f"{features['dbytes']}"
    )


    print(
        f"Rate: "
        f"{features['rate']:.2f} "
        f"packets/sec"
    )


    print(
        f"sinpkt: "
        f"{features['sinpkt']:.3f} ms"
    )


    print(
        f"dinpkt: "
        f"{features['dinpkt']:.3f} ms"
    )


    print(
        f"smean: "
        f"{features['smean']:.2f}"
    )


    print(
        f"dmean: "
        f"{features['dmean']:.2f}"
    )


    result = send_to_ai(
        features
    )


    if result is None:
        return


    print()

    print(
        "AI PREDICTION"
    )


    print(
        f"Event ID: "
        f"{result['event_id']}"
    )


    print(
        f"Prediction: "
        f"{result['prediction']}"
    )


    print(
        f"Risk Score: "
        f"{result['risk_score']}/100"
    )


    print(
        f"Severity: "
        f"{result['severity']}"
    )


    print(
        f"Attack probability: "
        f"{result['attack_probability']}"
    )


    # Save successful AI result
    save_live_flow(
        flow,
        features,
        result
    )


    print(
        "Saved to live_flows.csv"
    )


# ==========================================================
# Expire Flows
# ==========================================================

def expire_flows():

    now = time.time()

    expired_keys = []


    for key, flow in flows.items():

        inactive_time = (
            now
            -
            flow["last_time"]
        )


        if inactive_time >= FLOW_TIMEOUT:

            expired_keys.append(
                key
            )


    for key in expired_keys:

        flow = flows.pop(
            key
        )

        process_completed_flow(
            flow
        )


# ==========================================================
# Packet Callback
# ==========================================================

def process_packet(packet):

    update_flow(
        packet
    )

    expire_flows()


# ==========================================================
# Main
# ==========================================================

def main():

    print("=" * 76)

    print(
        "AI CYBERSECURITY PLATFORM"
    )

    print(
        "REAL-TIME AI NETWORK MONITOR"
    )

    print("=" * 76)

    print()

    print(
        f"Interface: {INTERFACE}"
    )

    print(
        f"Local IP: {LOCAL_IP}"
    )

    print(
        f"Flow timeout: "
        f"{FLOW_TIMEOUT}s"
    )

    print(
        f"AI endpoint: "
        f"{API_URL}"
    )

    print(
        f"CSV output: "
        f"{LIVE_DATA_PATH}"
    )

    print()

    print(
        "Only meaningful TCP/UDP flows "
        "will be analyzed."
    )

    print(
        "Analyzed flows will also be "
        "saved to CSV."
    )

    print()

    print(
        "Press CTRL+C to stop."
    )

    print()


    capture_filter = (
        f"ip and host {LOCAL_IP}"
    )


    try:

        sniff(
            iface=INTERFACE,
            filter=capture_filter,
            prn=process_packet,
            store=False
        )


    except KeyboardInterrupt:

        print()

        print(
            "Flushing remaining flows..."
        )


        for flow in list(
            flows.values()
        ):

            process_completed_flow(
                flow
            )


        flows.clear()

        print()

        print(
            "Real-time monitor stopped."
        )


if __name__ == "__main__":
    main()
