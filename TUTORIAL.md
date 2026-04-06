# Comprehensive Guide to Docker-ELK

Welcome to the `docker-elk` tutorial! This guide will walk you through what the Elastic Stack is, what this specific project does, and how to get it running on your machine from scratch.

## 🎯 What is Docker-ELK and What Functions Does it Have?

The Elastic Stack (formerly ELK stack) is a powerful suite of tools used for searching, analyzing, and visualizing large amounts of data in real time. This project (`docker-elk`) provides a pre-configured, containerized version of this stack using Docker, making it incredibly easy to spin up and test without manually installing complex dependencies on your host machine.

### Core Functions & Components:
1. **Elasticsearch**: The heart of the stack. It is a distributed, RESTful search and analytics engine where all your data is stored and indexed.
2. **Logstash**: A server-side data processing pipeline. It ingests data from a multitude of sources simultaneously, transforms it, and then sends it to Elasticsearch.
3. **Kibana**: The visualization layer. It provides a web interface where you can search, view, and create interactive dashboards (charts, graphs, maps) of the data stored in Elasticsearch.
4. **Extensions (Beats, Fleet, Curator)**: The project includes optional extensions out-of-the-box like `Filebeat` (for shipping log files), `Metricbeat` (for system metrics), and `Heartbeat` (for uptime monitoring).

---

## 🛠️ Prerequisites (What you need before setting up)

Before you begin, ensure your system has the following installed:
* **Docker Engine**: version 18.06.0 or newer.
* **Docker Compose**: version 2.0.0 or newer.
* **RAM**: At least 1.5 GB of RAM available for Docker (Docker Desktop for Mac/Windows often defaults to 2GB, which is sufficient for basic testing).

---

## 🚀 Setup & Deployment Guide

Follow these steps to deploy the stack on your local machine.

### Step 1: Get the Code
Clone the repository to your machine and navigate into the project folder:
```bash
git clone https://github.com/deviantony/docker-elk.git
cd docker-elk
```

### Step 2: Initial Setup (User Initialization)
The Elastic stack requires internal users to communicate securely. We need to initialize these users and their default passwords. Run the setup container:

```bash
docker compose up setup
```
Wait for it to finish. You should see logs indicating that users like `elastic`, `logstash_internal`, and `kibana_system` have been created or updated.

### Step 3: Start the ELK Stack
Once the setup completes successfully, you can deploy the core stack (Elasticsearch, Logstash, and Kibana) in the background (detached mode):

```bash
docker compose up -d
```

### Step 4: Access Kibana
Give the containers a minute or two to fully initialize. Then, open your web browser and navigate to:
**http://localhost:5601**

Log in using the default credentials:
* **Username**: `elastic`
* **Password**: `changeme` 

---

## 🔒 Securing Your Deployment (Highly Recommended)

The default password (`changeme`) is inherently insecure. It is highly recommended to change it immediately after your first successful deployment.

1. **Auto-generate a new password for the `elastic` user:**
   ```bash
   docker compose exec elasticsearch bin/elasticsearch-reset-password --batch --user elastic
   ```
   *(Save the generated password outputted in the terminal!)*

2. **Update the Configuration:**
   Open the `.env` file in the root of the `docker-elk` directory and replace the `ELASTIC_PASSWORD` value with your newly generated password. Do the same for `logstash_internal` and `kibana_system` by resetting their passwords and updating the `.env` file.

3. **Restart the Stack:**
   Restart Logstash and Kibana so they use the new credentials to talk to Elasticsearch:
   ```bash
   docker compose up -d logstash kibana
   ```

---

## 🧪 Testing the Setup (Injecting Data)

Now that everything is running, let's send some test data to Logstash! The provided Logstash configuration is set up to listen for TCP data on port `50000`.

You can use `nc` (Netcat) to send a simple message. Run this in your terminal:
```bash
# If you are on Mac / BSD:
echo "Hello ELK Stack! This is a test log." | nc -q0 localhost 50000

# If you are on Linux / GNU:
echo "Hello ELK Stack! This is a test log." | nc -c localhost 50000
```

Go back to Kibana, open the **Discover** tab, and you will see your log entry automatically indexed and ready to be visualized!

---

## 🤖 AI-Powered Threat Detection Scripts

This project also includes several custom Python scripts designed to integrate Machine Learning with the ELK stack for network intrusion detection:

* **`train_model.py`**: The core AI training script. It reads a network traffic dataset (UNSW-NB15), preprocesses the data (encoding and scaling), and trains an LSTM (Long Short-Term Memory) neural network using PyTorch. It saves the trained model (`lstm_model.pth`) and data scalers for real-time use.
* **`fetch_up.py`**: A utility script used to test the connection to Elasticsearch. It fetches the latest network logs from the `unsw-raw` index and formats them into a Pandas DataFrame, ensuring the data pipeline is working and ready to be fed into the AI.
* **`monitor.py`**: A background monitoring daemon. It continuously polls Elasticsearch every 5 seconds for new data in the `unsw-raw` index, evaluates the logs using the trained LSTM model, and if malicious traffic is detected, it pushes an alert directly to the `unsw-alerts` index.
* **`live_ai_traffic.py`**: A real-time Security Operations Center (SOC) script. It pulls live Zeek network logs (shipped by Filebeat), maps the Zeek log features to the AI model's expected format, and runs the intrusion detection model on the live traffic, immediately sending alerts to Kibana if an attack is detected.

### How to Run the AI Pipeline

To use the machine learning threat detection, you must run the scripts in a specific order:

**1. Install Python Dependencies**
Ensure you have Python 3 installed, then install the required libraries:
```bash
pip install pandas numpy torch scikit-learn joblib elasticsearch
```

**2. Train the AI Model**
Before the system can detect threats, it must be trained. Ensure your dataset (`UNSW_NB15_training-set.csv`) is in the project directory, then run:
```bash
python train_model.py
```
*This step might take a few minutes. Once finished, it will create an `ai_models/` folder containing the compiled `lstm_model.pth` and data scaler files.*

**3. Start the Real-Time SOC Monitor**
With the model trained and the ELK stack running, you can activate the AI monitoring. Choose **one** of the scripts based on your setup:

* **Option A (If using basic UNSW logs):**
  ```bash
  python monitor.py
  ```
* **Option B (If using live Zeek network logs via Filebeat):**
  ```bash
  python live_ai_traffic.py
  ```
*(Keep the terminal open. The script will run continuously, pulling data every 5 seconds and printing alerts to the console while pushing them to Kibana).*

**4. Utilities (Optional)**
If you want to test your data pipeline before starting the monitor, run:
```bash
python fetch_up.py
```

---

## 🧹 Teardown & Cleanup

If you are done experimenting and want to completely remove the stack and delete all the saved data, run:
```bash
docker compose --profile=setup down -v
```
This stops the containers and completely removes the Docker volumes where Elasticsearch data is permanently stored.
