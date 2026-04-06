import os
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import warnings
warnings.filterwarnings('ignore')

MODEL_DIR = "ai_models"
os.makedirs(MODEL_DIR, exist_ok=True)

# ===== HYPERPARAMETER (THÔNG SỐ TỐI ƯU HÓA) =====
# Khi viết báo cáo, bạn thay đổi các số này vài lần để tìm ra kết quả tốt nhất
BATCH_SIZE = 256
HIDDEN_SIZE = 64
LEARNING_RATE = 0.001
EPOCHS = 5

print("[*] Đọc và Tiền xử lý dữ liệu...")
df = pd.read_csv('UNSW_NB15_training-set.csv')
if 'id' in df.columns: df = df.drop(columns=['id'])
if 'attack_cat' in df.columns: df = df.drop(columns=['attack_cat'])

categorical_cols = df.select_dtypes(include=['object']).columns
encoders = {}
for col in categorical_cols:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))
    encoders[col] = le
joblib.dump(encoders, os.path.join(MODEL_DIR, 'label_encoders.pkl'))

X = df.drop(columns=['label'])
y = df['label'].values

scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)
joblib.dump(scaler, os.path.join(MODEL_DIR, 'minmax_scaler.pkl'))

# ===== CHIA DỮ LIỆU TỈ LỆ 7:2:1 =====
print("[*] Chia tập dữ liệu Train (70%) - Val (20%) - Test (10%)...")
# Bước 1: Tách 10% ra làm Test
X_temp, X_test, y_temp, y_test = train_test_split(X_scaled, y, test_size=0.1, random_state=42)
# Bước 2: Tách 90% còn lại (X_temp) thành 70% Train và 20% Val
# Tỉ lệ 20/90 = 0.2222
X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.2222, random_state=42)

# Ép kiểu Tensor
def make_tensor(X_data, y_data):
    return torch.tensor(X_data, dtype=torch.float32).unsqueeze(1), torch.tensor(y_data, dtype=torch.float32).unsqueeze(1)

X_train_t, y_train_t = make_tensor(X_train, y_train)
X_val_t, y_val_t = make_tensor(X_val, y_val)
X_test_t, y_test_t = make_tensor(X_test, y_test)

train_loader = DataLoader(TensorDataset(X_train_t, y_train_t), batch_size=BATCH_SIZE, shuffle=True)
val_loader = DataLoader(TensorDataset(X_val_t, y_val_t), batch_size=BATCH_SIZE, shuffle=False)

# ===== THIẾT KẾ KIẾN TRÚC MÔ HÌNH =====
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

model = IntrusionLSTM(input_size=X.shape[1], hidden_size=HIDDEN_SIZE)
criterion = nn.BCELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

# ===== HUẤN LUYỆN (TRAINING) =====
print("\n[*] Bắt đầu huấn luyện...")
for epoch in range(EPOCHS):
    model.train()
    train_loss = 0
    for batch_X, batch_y in train_loader:
        optimizer.zero_grad()
        outputs = model(batch_X)
        loss = criterion(outputs, batch_y)
        loss.backward()
        optimizer.step()
        train_loss += loss.item()
    
    # Kiểm tra trên tập Validation
    model.eval()
    val_loss = 0
    with torch.no_grad():
        for val_X, val_y in val_loader:
            outputs = model(val_X)
            loss = criterion(outputs, val_y)
            val_loss += loss.item()
            
    print(f"    -> Vòng {epoch+1}/{EPOCHS} | Train Loss: {train_loss/len(train_loader):.4f} | Val Loss: {val_loss/len(val_loader):.4f}")

model_path = os.path.join(MODEL_DIR, 'lstm_model.pth')
torch.save(model.state_dict(), model_path)

# ===== ĐÁNH GIÁ SƠ BỘ (TESTING) =====
print("\n[*] ĐÁNH GIÁ MÔ HÌNH TRÊN TẬP TEST (10%)...")
model.eval()
with torch.no_grad():
    y_pred_probs = model(X_test_t).numpy()
    y_pred_labels = (y_pred_probs > 0.5).astype(int)
    y_true = y_test_t.numpy()

print("1. Báo cáo phân loại (Precision, Recall, F1-Score):")
print(classification_report(y_true, y_pred_labels, target_names=['Normal', 'Attack']))

print("2. Ma trận nhầm lẫn (Confusion Matrix):")
print(confusion_matrix(y_true, y_pred_labels))

roc_auc = roc_auc_score(y_true, y_pred_probs)
print(f"3. Chỉ số ROC/AUC Score: {roc_auc:.4f}")