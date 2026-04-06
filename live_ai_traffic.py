import os
import time
import pandas as pd
import torch
import torch.nn as nn
import joblib
from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings('ignore')

# ==========================================
# 1. CẤU HÌNH TRẠM GÁC TRUNG TÂM
# ==========================================
MODEL_DIR = "ai_models"
INDEX_SOURCE = "*"  # Kho chứa đạn: Nơi Filebeat đổ log Zeek vào
INDEX_ALERT = "unsw-alerts"  # Màn hình radar: Nơi đẩy cảnh báo lên Kibana

print("[*] Đang kết nối với Căn cứ dữ liệu Elasticsearch...")
ES_CLIENT = Elasticsearch("http://localhost:9200", basic_auth=("elastic", "changeme"))

print("[*] Đang đánh thức Não bộ AI LSTM...")
encoders = joblib.load(os.path.join(MODEL_DIR, 'label_encoders.pkl'))
scaler = joblib.load(os.path.join(MODEL_DIR, 'minmax_scaler.pkl'))
expected_features = scaler.feature_names_in_

# ==========================================
# 2. KIẾN TRÚC MÔ HÌNH AI
# ==========================================
class IntrusionLSTM(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers=2):
        super(IntrusionLSTM, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, 1)
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        out, _ = self.lstm(x)
        return self.sigmoid(self.fc(out[:, -1, :]))

model = IntrusionLSTM(input_size=len(expected_features), hidden_size=64)
model.load_state_dict(torch.load(os.path.join(MODEL_DIR, 'lstm_model.pth')))
model.eval()

# ==========================================
# 3. QUY TRÌNH SĂN LÙNG THỜI GIAN THỰC
# ==========================================
def process_and_predict(source_data, log_timestamp):
    # Trích xuất dữ liệu từ Logstash đổ về
    src_ip = source_data.get('id.orig_h')
    if not src_ip: return # Không phải log Zeek thì bỏ qua

    dst_ip = source_data.get('id.resp_h', 'Unknown')
    proto = source_data.get('proto', 'tcp')
    
    # Tạo bảng 47 đặc trưng trống
    mapped_data = {col: 0 for col in expected_features}
    
    # Lắp đạn (Map data từ Zeek sang format UNSW)
    mapped_data['dur'] = source_data.get('duration', 0.0)
    mapped_data['proto'] = proto
    mapped_data['service'] = source_data.get('service', '-')
    mapped_data['state'] = source_data.get('conn_state', 'INT')
    mapped_data['spkts'] = source_data.get('orig_pkts', 0)
    mapped_data['dpkts'] = source_data.get('resp_pkts', 0)
    mapped_data['sbytes'] = source_data.get('orig_bytes', 0)
    mapped_data['dbytes'] = source_data.get('resp_bytes', 0)
    
    df_live = pd.DataFrame([mapped_data])
    
    # Phiên dịch chữ sang số cho AI
    for col, le in encoders.items():
        if col in df_live.columns:
            val = str(df_live[col].iloc[0])
            df_live[col] = le.transform([val])[0] if val in le.classes_ else le.transform([le.classes_[0]])[0]
            
    # Chuẩn hóa và dự đoán
    df_live = df_live[expected_features]
    X_scaled = scaler.transform(df_live)
    X_tensor = torch.tensor(X_scaled, dtype=torch.float32).unsqueeze(1)
    
    with torch.no_grad():
        prob = model(X_tensor).item()
        
    # NẾU TỈ LỆ > 50% LÀ BÁO ĐỘNG!
    if prob > 0.50:
        print(f"[🚨 TẤN CÔNG] Kẻ thù: {src_ip} -> Mục tiêu: {dst_ip} | Rủi ro: {prob*100:.2f}% | Protocol: {proto}")
        
        # Bắn báo động lên Kibana Dashboard
        alert_doc = {
            "@timestamp": log_timestamp,
            "threat_score": prob,
            "status": "ATTACK_DETECTED",
            "srcip": src_ip,
            "dstip": dst_ip
        }
        ES_CLIENT.index(index=INDEX_ALERT, document=alert_doc)
    else:
        print(f"[✅ AN TOÀN] Traffic từ {src_ip} | Rủi ro: {prob*100:.2f}%")

# ==========================================
# 4. RADAR QUÉT LIÊN TỤC
# ==========================================
print(f"\n[+] HỆ THỐNG SOC PHÂN TÁN ĐÃ KÍCH HOẠT!")
print(f"[*] Đang trực chiến, chờ đợi tín hiệu từ Tiền đồn Zeek...\n")

# Bắt đầu quét từ thời điểm hiện tại
last_timestamp = "now-1d" 

while True:
    try:
        query = {
            "query": { "match_all": {} }, # Quét sạch không điều kiện
            "sort": [{"@timestamp": {"order": "desc"}}], # Lấy cái mới nhất lên đầu
            "size": 5
        }
        
        res = ES_CLIENT.search(index=INDEX_SOURCE, body=query, ignore_unavailable=True)
        hits = res['hits']['hits']
        
        if not hits:
            print("[...] Radar đang quét nhưng chưa thấy dữ liệu Zeek nào trong kho.")
        
        for hit in hits:
            source_data = hit['_source']
            # IN RA TẤT CẢ CÁC CỘT ĐỂ KIỂM TRA
            print(f"[*] Đã thấy 1 dòng log! Các cột có sẵn: {list(source_data.keys())[:10]}...")
            
            process_and_predict(source_data, source_data.get('@timestamp'))
            
        time.sleep(5)
        
    except Exception as e:
        print(f"[-] Lỗi Radar: {e}")
        time.sleep(5)