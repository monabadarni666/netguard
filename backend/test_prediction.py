from pathlib import Path
import json

import pandas as pd
import requests


BASE_DIR = Path(__file__).resolve().parent.parent

TEST_DATA_PATH = BASE_DIR / "ml" / "data" / "UNSW_NB15_testing-set.csv"
CONFIG_PATH = BASE_DIR / "ml" / "models" / "model_config.json"

API_URL = "http://127.0.0.1:8000/predict"


# Load model configuration
with open(CONFIG_PATH, "r") as file:
    config = json.load(file)


# Load test dataset
test_df = pd.read_csv(TEST_DATA_PATH)


# Take one real network-flow example
sample = test_df.iloc[0]


# Keep only the 42 features expected by the model
sample_features = sample[config["feature_columns"]]


# Convert pandas/numpy values into normal JSON values
payload = json.loads(sample_features.to_json())


# Send the network flow to the FastAPI backend
response = requests.post(
    API_URL,
    json=payload,
    timeout=30
)


print("HTTP Status:", response.status_code)

print("\nExpected from dataset:")
print("Label:", sample["label"])
print("Attack category:", sample["attack_cat"])

print("\nAI API prediction:")
print(json.dumps(response.json(), indent=4))
