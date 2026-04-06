import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib
import requests
import time
import warnings
warnings.filterwarnings('ignore')
from flask import Flask, request, jsonify

app = Flask(__name__)   
# --- Configuration ---
MODEL_DIR = "ai_models"
MODEL_PATH = os.path.join(MODEL_DIR, 'lstm_model.pth')
SCALER_PATH = os.path.join(MODEL_DIR, 'minmax_scaler.pkl')
ENCODERS_PATH = os.path.join(MODEL_DIR, 'label_encoders.pkl')
COLUMNS_PATH = os.path.join(MODEL_DIR, 'feature_columns.pkl')

# --- Telegram Bot Configuration ---
# IMPORTANT: Replace with your Bot Token and Chat ID
# 1. Get Token: Talk to @BotFather on Telegram and create a new bot.
# 2. Get Chat ID: Talk to @userinfobot on Telegram.
TELEGRAM_BOT_TOKEN = "8646038974:AAEV6TR8S-DnNmues-Hvbqt2yS1CBSXf17s"
TELEGRAM_CHAT_ID = "6144456029"

# --- Model Definition ---
# The model class must be defined exactly as it was during training
class IntrusionLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers=2):
        super(IntrusionLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])
        return self.sigmoid(out)

# --- Helper Functions ---

def send_telegram_alert(message):
    """Sends a message to a Telegram chat."""
    if TELEGRAM_BOT_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN" or TELEGRAM_CHAT_ID == "YOUR_TELEGRAM_CHAT_ID":
        print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! Telegram bot not configured. Please edit this script.     !!!")
        print("!!! ALERT (not sent): An attack was detected.                 !!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            print("[+] Telegram alert sent successfully.")
        else:
            print(f"[-] Failed to send Telegram alert. Status: {response.status_code}, Response: {response.text}")
    except Exception as e:
        print(f"[-] An error occurred while sending Telegram alert: {e}")


def preprocess_input(data, encoders, scaler, feature_columns):
    """Preprocesses a single row of input data (as a dictionary or pd.Series)."""
    df = pd.DataFrame([data])

    # Apply label encoders
    for col, le in encoders.items():
        if col in df.columns:
            # Handle unseen labels by assigning a default value (-1)
            df[col] = df[col].astype(str).apply(lambda x: le.transform([x])[0] if x in le.classes_ else -1)

    # Ensure all feature columns are present, fill missing with 0, and order correctly
    for col in feature_columns:
        if col not in df.columns:
            df[col] = 0
    df = df[feature_columns]

    # Scale features
    scaled_data = scaler.transform(df)
    return torch.tensor(scaled_data, dtype=torch.float32).unsqueeze(1)


# --- Main Detection Logic ---

def main():
    print("[*] Loading model and preprocessors...")
    if not all(os.path.exists(p) for p in [MODEL_PATH, SCALER_PATH, ENCODERS_PATH, COLUMNS_PATH]):
        print("[-] Model files not found in 'ai_models/' directory.")
        print("[-] Please run the modified 'train_model.py' first to generate them.")
        return

    scaler = joblib.load(SCALER_PATH)
    encoders = joblib.load(ENCODERS_PATH)
    feature_columns = joblib.load(COLUMNS_PATH)
    input_size = len(feature_columns)

    # The hidden size must match the one used for training
    HIDDEN_SIZE = 64 # From train_model.py
    model = IntrusionLSTM(input_size=input_size, hidden_size=HIDDEN_SIZE)
    model.load_state_dict(torch.load(MODEL_PATH))
    model.eval()
    print("[+] Model loaded successfully.")

    print("\n[*] Starting simulated real-time detection...")
    print("    (Reading from 'UNSW_NB15_training-set.csv' to simulate incoming traffic)")

    try:
        data_stream = pd.read_csv('UNSW_NB15_training-set.csv', chunksize=1, iterator=True)

        for i, row_df in enumerate(data_stream):
            input_data = row_df.iloc[0].to_dict()
            
            # Remove columns not used for prediction
            true_label = input_data.pop('label', None)
            for col_to_drop in ['id', 'attack_cat']:
                if col_to_drop in input_data:
                    del input_data[col_to_drop]

            processed_tensor = preprocess_input(input_data, encoders, scaler, feature_columns)
            
            with torch.no_grad():
                prediction_prob = model(processed_tensor).item()
                prediction = 1 if prediction_prob > 0.5 else 0

            print(f"Packet {i+1: <6} | Prediction: {'ATTACK' if prediction == 1 else 'Normal'} (Prob: {prediction_prob:.4f}) | Actual: {'Attack' if true_label == 1 else 'Normal'}")

            if prediction == 1:
                print("!!! ATTACK DETECTED !!!")
                alert_message = f"🚨 *Network Attack Alert!* 🚨\n\nAn attack has been detected by the LSTM model.\n\n*Confidence:* `{prediction_prob:.2%}`\n*Timestamp:* `{pd.Timestamp.now()}`"
                send_telegram_alert(alert_message)
                print("[*] Pausing for 10 seconds to avoid alert spam...")
                time.sleep(10)
            
            time.sleep(0.05) # Simulate small delay between packets

    except KeyboardInterrupt:
        print("\n[*] Detection stopped by user.")
    except FileNotFoundError:
        print("[-] Error: 'UNSW_NB15_training-set.csv' not found. Please place it in the same directory.")

if __name__ == "__main__":
    main()
  