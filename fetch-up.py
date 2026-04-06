from elasticsearch import Elasticsearch
import pandas as pd

# 1. Kết nối với Elasticsearch (Dùng đúng tài khoản admin lúc nãy)
es = Elasticsearch(
    "http://localhost:9200",
    basic_auth=("elastic", "changeme")
)

def get_latest_logs(index_name="unsw-raw", batch_size=10):
    # 2. Câu Query lấy log mới nhất
    query = {
        "query": {"match_all": {}},
        "sort": [{"@timestamp": {"order": "desc"}}],
        "size": batch_size
    }

    print(f"[*] Đang kéo {batch_size} log mới nhất từ Elasticsearch...")
    response = es.search(index=index_name, body=query)

    # 3. Biến đống JSON phức tạp thành bảng Pandas gọn gàng
    logs = [hit['_source'] for hit in response['hits']['hits']]
    df = pd.DataFrame(logs)
    
    return df

if __name__ == "__main__":
    if es.ping():
        print("[+] Kết nối Elasticsearch thành công!")
        df_logs = get_latest_logs()
        print("[+] Dữ liệu đã sẵn sàng để đưa vào AI. Dưới đây là 5 dòng mẫu:")
        print(df_logs.head())
    else:
        print("[-] Lỗi kết nối! Hãy kiểm tra lại Elasticsearch.")