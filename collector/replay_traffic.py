from pathlib import Path
import json
import random
import time

import pandas as pd
import requests


BASE_DIR = Path(__file__).resolve().parent.parent

TEST_DATA_PATH = (
    BASE_DIR
    / "ml"
    / "data"
    / "UNSW_NB15_testing-set.csv"
)

CONFIG_PATH = (
    BASE_DIR
    / "ml"
    / "models"
    / "model_config.json"
)

API_URL = "http://127.0.0.1:8000/predict"

DELAY_SECONDS = 1


def load_configuration():
    with open(CONFIG_PATH, "r") as file:
        return json.load(file)


def load_dataset():
    return pd.read_csv(TEST_DATA_PATH)


def create_payload(sample, feature_columns):
    features = sample[feature_columns]

    return json.loads(
        features.to_json()
    )


def send_flow(payload):
    response = requests.post(
        API_URL,
        json=payload,
        timeout=30
    )

    response.raise_for_status()

    return response.json()


def main():

    print()
    print("=" * 60)
    print("AI CYBERSECURITY PLATFORM")
    print("LIVE NETWORK FLOW REPLAY")
    print("=" * 60)

    config = load_configuration()

    dataset = load_dataset()

    feature_columns = config["feature_columns"]

    print(f"Loaded {len(dataset)} network flows.")
    print(f"Sending one flow every {DELAY_SECONDS} second(s).")
    print()
    print("Press CTRL+C to stop.")
    print()

    counter = 0

    try:

        while True:

            # Pick a random flow
            index = random.randint(
                0,
                len(dataset) - 1
            )

            sample = dataset.iloc[index]

            payload = create_payload(
                sample,
                feature_columns
            )

            result = send_flow(payload)

            actual_label = int(
                sample["label"]
            )

            actual = (
                "ATTACK"
                if actual_label == 1
                else "NORMAL"
            )

            predicted = result["prediction"]

            risk_score = result["risk_score"]

            severity = result["severity"]

            event_id = result["event_id"]

            correct = (
                "✓"
                if actual == predicted
                else "✗"
            )

            counter += 1

            print(
                f"[{counter:04d}] "
                f"Event #{event_id} | "
                f"Actual: {actual:<6} | "
                f"AI: {predicted:<6} | "
                f"Risk: {risk_score:>6.2f} | "
                f"{severity:<8} | "
                f"{correct}"
            )

            time.sleep(
                DELAY_SECONDS
            )

    except KeyboardInterrupt:

        print()
        print()
        print("Live traffic replay stopped.")
        print(
            f"Total flows sent: {counter}"
        )


if __name__ == "__main__":
    main()
