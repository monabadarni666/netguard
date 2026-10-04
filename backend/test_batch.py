from pathlib import Path
import json

import pandas as pd
import requests


BASE_DIR = Path(__file__).resolve().parent.parent

TEST_DATA_PATH = BASE_DIR / "ml" / "data" / "UNSW_NB15_testing-set.csv"
CONFIG_PATH = BASE_DIR / "ml" / "models" / "model_config.json"

API_URL = "http://127.0.0.1:8000/predict"

NUMBER_OF_SAMPLES = 100


# Load configuration
with open(CONFIG_PATH, "r") as file:
    config = json.load(file)


# Load test dataset
test_df = pd.read_csv(TEST_DATA_PATH)


# Take 100 random samples
samples = test_df.sample(
    n=NUMBER_OF_SAMPLES,
    random_state=42
)


correct = 0

true_positives = 0
true_negatives = 0
false_positives = 0
false_negatives = 0

risk_scores = []


for _, sample in samples.iterrows():

    sample_features = sample[config["feature_columns"]]

    payload = json.loads(
        sample_features.to_json()
    )

    response = requests.post(
        API_URL,
        json=payload,
        timeout=30
    )

    if response.status_code != 200:
        print("Request failed:", response.status_code)
        continue

    result = response.json()

    predicted_label = (
        1
        if result["prediction"] == "ATTACK"
        else 0
    )

    actual_label = int(sample["label"])

    risk_scores.append(
        result["risk_score"]
    )

    if predicted_label == actual_label:
        correct += 1

    if actual_label == 1 and predicted_label == 1:
        true_positives += 1

    elif actual_label == 0 and predicted_label == 0:
        true_negatives += 1

    elif actual_label == 0 and predicted_label == 1:
        false_positives += 1

    elif actual_label == 1 and predicted_label == 0:
        false_negatives += 1


accuracy = correct / NUMBER_OF_SAMPLES * 100

average_risk = (
    sum(risk_scores) / len(risk_scores)
    if risk_scores
    else 0
)


print("\nAI CYBERSECURITY PLATFORM - API TEST")
print("--------------------------------------")

print("Flows analyzed:", NUMBER_OF_SAMPLES)

print(f"Accuracy: {accuracy:.2f}%")

print("\nTrue Positives :", true_positives)
print("True Negatives :", true_negatives)
print("False Positives:", false_positives)
print("False Negatives:", false_negatives)

print(
    f"\nAverage Risk Score: {average_risk:.2f}/100"
)
