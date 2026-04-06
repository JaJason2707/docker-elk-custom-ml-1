import os
import time
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from elasticsearch import Elasticsearch
import warnings
warnings.filterwarnings('ignore')

# ==========================================
# 1. CẤU HÌNH HỆ THỐNG & TẠO FOLDER
# ==========================================
OUTPUT_DIR = "k-cluster"
INDEX_SOURCE = "*"  # Quét toàn bộ để gom cụm (có thể đổi thành logstash-* nếu muốn)

# Tạo folder tự động nếu chưa có
os.makedirs(OUTPUT_DIR, exist_ok=True)
print(f"[*] Đã sẵn sàng thư mục xuất báo cáo: ./{OUTPUT_DIR}/")

print("[*] Đang kết nối với Căn cứ dữ liệu Elasticsearch...")
ES_CLIENT = Elasticsearch("http://localhost:9200", basic_auth=("elastic", "changeme"))

# ==========================================
# 2. HÚT DỮ LIỆU TỪ ELASTICSEARCH
# ==========================================
def fetch_data_for_clustering():
    print("[*] Đang thu thập dữ liệu gói tin để phân tích...")
    query = {
        "query": { "match_all": {} },
        "size": 10000,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    
    try:
        res = ES_CLIENT.search(index=INDEX_SOURCE, body=query, ignore_unavailable=True)
        hits = res['hits']['hits']
        
        if not hits:
            print("[-] Không tìm thấy dữ liệu nào trong kho. Hãy bắn hping3 rồi chạy lại nhé!")
            return None
            
        data_list = []
        
        # --- THÊM 2 DÒNG NÀY ĐỂ SOI DATA ---
        if len(hits) > 0:
            print(f"[🔍 NỘI SOI DATA] Dòng log mới nhất đang có các cột này: {list(hits[0]['_source'].keys())[:15]}")
        # -----------------------------------

        for hit in hits:
            source = hit['_source']
            # Kiểm tra xem có lấy được IP không
            if 'id.orig_h' in source or 'source.ip' in source:
                data_list.append({
                    'timestamp': source.get('@timestamp'),
                    'src_ip': source.get('id.orig_h', source.get('source.ip', 'Unknown')),
                    'dst_ip': source.get('id.resp_h', source.get('destination.ip', 'Unknown')),
                    'proto': source.get('proto', source.get('network.transport', 'tcp')),
                    'duration': float(source.get('duration', 0.0)),
                    'orig_bytes': float(source.get('orig_bytes', source.get('source.bytes', 0.0))),
                    'resp_bytes': float(source.get('resp_bytes', source.get('destination.bytes', 0.0))),
                    'orig_pkts': float(source.get('orig_pkts', source.get('source.packets', 0.0))),
                    'resp_pkts': float(source.get('resp_pkts', source.get('destination.packets', 0.0)))
                })
        
        df = pd.DataFrame(data_list)
        print(f"[+] Đã thu thập thành công {len(df)} gói tin hợp lệ.")
        return df
    except Exception as e:
        print(f"[-] Lỗi khi rút dữ liệu: {e}")
        return None

# ==========================================
# 3. THUẬT TOÁN K-MEANS & XUẤT BẢNG
# ==========================================
def run_clustering(df):
    if df is None or df.empty:
        return

    print("\n[*] Đang khởi động Thuật toán K-means (gom 3 cụm)...")
    
    # Lấy các cột số để đưa vào K-means
    features = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']
    X = df[features].fillna(0) # Điền 0 nếu thiếu dữ liệu
    
    # CHUẨN HÓA DỮ LIỆU (Bắt buộc với K-means để tránh bị lệch số liệu)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    # Chạy K-means
    kmeans = KMeans(n_clusters=3, random_state=42, n_init=10)
    df['Cluster_ID'] = kmeans.fit_predict(X_scaled)
    
    # Gán tên cho dễ hiểu trong báo cáo đồ án
    cluster_names = {
        0: "Cụm 0 (Traffic Bình Thường)",
        1: "Cụm 1 (Nghi ngờ Quét Cổng/Scan)",
        2: "Cụm 2 (Nghi ngờ Tấn công DoS/DDoS)"
    }
    df['Cluster_Name'] = df['Cluster_ID'].map(cluster_names)

    # --- TẠO BẢNG TỔNG HỢP ---
    summary_df = df.groupby('Cluster_Name')[features].mean().round(2)
    summary_df['Total_Packets_Analyzed'] = df.groupby('Cluster_Name').size()
    
    print("\n[📊 BẢNG TỔNG HỢP K-MEANS ĐÃ HOÀN THÀNH]")
    print("-" * 60)
    print(summary_df.to_string())
    print("-" * 60)
    
    # --- XUẤT RA FILE TRONG FOLDER k-cluster ---
    timestamp_str = time.strftime("%Y%m%d_%H%M%S")
    
    # 1. File chi tiết (từng IP một)
    detail_file = os.path.join(OUTPUT_DIR, f"kmeans_detail_{timestamp_str}.csv")
    df.to_csv(detail_file, index=False)
    
    # 2. File bảng tóm tắt (để copy vào Word làm báo cáo)
    summary_file = os.path.join(OUTPUT_DIR, f"kmeans_summary_{timestamp_str}.csv")
    summary_df.to_csv(summary_file)
    
    print(f"\n[✅] THÀNH CÔNG! Toàn bộ dữ liệu đã được xuất vào thư mục: {OUTPUT_DIR}/")
    print(f"  -> File chi tiết: {detail_file}")
    print(f"  -> File tóm tắt:  {summary_file}")

# ==========================================
# 4. KÍCH HOẠT HỆ THỐNG
# ==========================================
if __name__ == "__main__":
    df_live = fetch_data_for_clustering()
    run_clustering(df_live)