import os
import time
import pandas as pd
import torch
import torch.nn as nn
import joblib
from elasticsearch import Elasticsearch
import requests # Thêm thư viện để gọi API
import warnings
warnings.filterwarnings('ignore')
import json

# 1. CẤU HÌNH HỆ THỐNG
MODEL_DIR = "ai_models"
INDEX_RAW = "*" # Quét tất cả các index, tương tự live_ai_traffic.py
INDEX_ALERT = "unsw-alerts"
DETECTOR_API_URL = "http://localhost:5001/alert" # API của detector.py
ES_CLIENT = Elasticsearch("http://localhost:9200", basic_auth=("elastic", "changeme"))

# 2. KHÔI PHỤC "NÃO BỘ" VÀ TỪ ĐIỂN
print("[*] Đang đánh thức AI và nạp từ điển...")
encoders = joblib.load(os.path.join(MODEL_DIR, 'label_encoders.pkl'))
scaler = joblib.load(os.path.join(MODEL_DIR, 'minmax_scaler.pkl'))

class IntrusionLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers):
        super(IntrusionLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])
        return self.sigmoid(out)

# Khởi tạo mô hình trống và nhét "kiến thức" (.pth) vào
input_features = len(scaler.data_min_) # Lấy đúng số lượng feature lúc train
model = IntrusionLSTM(input_size=input_features, hidden_size=64, num_layers=2)
model.load_state_dict(torch.load(os.path.join(MODEL_DIR, 'lstm_model.pth')))
model.eval() # Chuyển sang chế độ phán đoán (không học nữa)
print("[+] AI đã sẵn sàng chiến đấu!")

# 3. HÀM GIÁM SÁT
# --- THÊM BIẾN NÀY ĐỂ THEO DÕI THỜI GIAN ---
last_timestamp = None 

# 3. HÀM GIÁM SÁT
def scan_network_traffic():
    global last_timestamp # Gọi biến toàn cục để cập nhật sau mỗi vòng lặp
    print("\n[*] Đang quét log mạng mới nhất từ Elasticsearch...")
    
    # --- THAY ĐỔI CÚ PHÁP TRUY VẤN TẠI ĐÂY ---
    if last_timestamp:
        # Nếu đã có mốc thời gian, chỉ lấy log CÓ SAU mốc thời gian đó
        query = {
            "query": {
                 "bool": {
                    "must": [
                     # Chỉ lấy log của Zeek (hoặc network_traffic nếu dùng Packetbeat)
                     {"term": {"event.dataset": "zeek.connection"}} 
            ],
            "filter": [
                {"range": {"@timestamp": {"gte": "now-1m"}}} # Lấy 1 phút gần nhất
            ]
        }
    }

        }
    else:
        # Lần chạy đầu tiên (chưa có mốc thời gian), lấy 10 log mới nhất
        query = {
            "query": {"match_all": {}}, 
            "sort": [{"@timestamp": {"order": "desc"}}], 
            "size": 10
        }
    
    response = ES_CLIENT.search(index=INDEX_RAW, body=query, ignore_unavailable=True)
    hits = response['hits']['hits']
    
    if not hits:
        print("[-] Không có dữ liệu mạng nào mới.")
        return

    # --- LƯU LẠI MỐC THỜI GIAN MỚI NHẤT ---
    # Vì chúng ta sort 'desc' (giảm dần), log ở vị trí hits[0] luôn là log mới nhất
    current_latest_time = hits[0]['_source'].get('@timestamp')
    if current_latest_time:
        last_timestamp = current_latest_time

    # Lọc lấy data thô
    logs = []
    log_ids = []
    for hit in hits:
        print("--- DỮ LIỆU THÔ TỪ ELK ---")
        print(json.dumps(hit['_source'], indent=2))
        break # Chỉ in 1 cái thôi cho đỡ rác màn hình
        source = hit['_source']
        # Bỏ đi các trường rác do Logstash tự sinh ra để khớp với lúc Train
        clean_log = {k: v for k, v in source.items() if k not in ['@timestamp', '@version', 'event', 'log', 'label', 'id', 'attack_cat']}
        logs.append(clean_log)
        log_ids.append(hit['_id'])

    df = pd.DataFrame(logs)
    
    # Tiền xử lý dữ liệu mới kéo về
    try:
        # Dịch chữ sang số (Xử lý an toàn nếu gặp chữ lạ chưa từng học)
        for col, le in encoders.items():
            if col in df.columns:
                df[col] = df[col].astype(str).map(lambda s: s if s in le.classes_ else le.classes_[0])
                df[col] = le.transform(df[col])
        
        # Đảm bảo đúng thứ tự cột như lúc train
        df = df.reindex(columns=scaler.feature_names_in_, fill_value=0)
        
        # Chuẩn hóa số
        X_scaled = scaler.transform(df)
        X_tensor = torch.tensor(X_scaled, dtype=torch.float32).unsqueeze(1)
        
        # AI đưa ra phán đoán
        with torch.no_grad():
            predictions = model(X_tensor)
            # Chèn vào trước dòng 116: predictions = model(X_tensor)
        print(f"DEBUG - Hình dáng Tensor: {X_tensor.shape}")
        print(f"DEBUG - Giá trị Tensor: {X_tensor}")
        
        # Xử lý kết quả và Báo động
        for i, pred in enumerate(predictions):
            prob = pred.item()
            is_attack = prob > 0.5 # Ngưỡng 50%
            
            if is_attack:
                log_details = hits[i]['_source']
                timestamp = log_details.get('@timestamp')
                src_ip = log_details.get('srcip', 'unknown')
                dst_ip = log_details.get('dstip', 'unknown')

                print(f"[🚨 CẢNH BÁO] Phát hiện TẤN CÔNG! (Tỉ lệ: {prob*100:.2f}%) | ID Log: {log_ids[i]}")

                # Gửi luồng dữ liệu tấn công qua detector.py để bắn cảnh báo Telegram
                try:
                    alert_payload = {
                        "threat_score": prob,
                        "timestamp": timestamp,
                        "srcip": src_ip,
                        "dstip": dst_ip
                    }
                    requests.post(DETECTOR_API_URL, json=alert_payload, timeout=5)
                    print(f"[+] Đã chuyển tiếp cảnh báo (ID: {log_ids[i]}) cho detector.py xử lý.")
                except requests.exceptions.RequestException as e:
                    print(f"[-] Lỗi khi gửi cảnh báo qua detector.py: {e}")

                # Đẩy cảnh báo lên Elasticsearch để lưu trữ và hiển thị trên Kibana
                alert_doc = {
                    "@timestamp": timestamp,
                    "original_log_id": log_ids[i],
                    "threat_score": prob,
                    "status": "ATTACK_DETECTED",
                    "srcip": src_ip,
                    "dstip": dst_ip
                }
                ES_CLIENT.index(index=INDEX_ALERT, document=alert_doc)
            else:
                print(f"[✅ AN TOÀN] Luồng mạng bình thường. (Tỉ lệ rủi ro: {prob*100:.2f}%)")
                
    except Exception as e:
        print(f"[-] Lỗi tiền xử lý: {e}")
        
if __name__ == "__main__":
    # Chạy vòng lặp vô tận, cứ 5 giây quét 1 lần
    try:
        while True:
            scan_network_traffic()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Đã tắt hệ thống giám sát.")