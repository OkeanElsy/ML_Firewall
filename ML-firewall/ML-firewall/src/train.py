# src/train_deep.py
import pandas as pd  # <--- To'g'ri: pd bu Pandas
import numpy as np
import joblib
import os

# Deep Learning kutubxonalari
import tensorflow as tf # <--- To'g'ri: tensorflow ni tf deb chaqiramiz
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

def train_deep_model():
    print("==========================================")
    print("[*] 1. NEURAL NETWORK UCHUN DATASET YUKLANMOQDA...")
    
    # Dataset ustunlari
    columns = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
               "wrong_fragment","urgent","hot","num_failed_logins","logged_in",
               "num_compromised","root_shell","su_attempted","num_root","num_file_creations",
               "num_shells","num_access_files","num_outbound_cmds","is_host_login",
               "is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
               "rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
               "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
               "dst_host_same_srv_rate","dst_host_diff_srv_rate",
               "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
               "dst_host_serror_rate","dst_host_srv_serror_rate",
               "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]

    try:
        # Faylni o'qish (Endi xato bermaydi, chunki pd = pandas)
        df = pd.read_csv(r"/home/okean/ML-firewall/data/KDDTrain+.txt", names=columns)
    except FileNotFoundError:
        print("[!] Xatolik: Dataset topilmadi!")
        return

    # Kerakli ustunlarni tanlash
    selected_features = ["protocol_type", "src_bytes", "dst_bytes", "count", "srv_count", "same_srv_rate", "diff_srv_rate", "label"]
    df = df[selected_features]

    print("[*] 2. MA'LUMOTLARNI PREPROCESSING QILISH...")

    # 1. Protokolni raqamlash
    le_proto = LabelEncoder()
    df['protocol_type'] = le_proto.fit_transform(df['protocol_type'])

    # 2. Labelni 0 va 1 ga o'girish
    df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

    X = df.drop('label', axis=1)
    y = df['label']

    # 3. SCALING
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Yordamchi fayllarni saqlash
    if not os.path.exists('models'): os.makedirs('models')
    joblib.dump(le_proto, '/home/okean/ML-firewall/models/proto_encoder.pkl')
    joblib.dump(scaler, '/home/okean/ML-firewall/models//scaler.pkl')

    print("[*] 3. NEYRON TARMOQ ARXITEKTURASINI QURISH...")
    
    # --- MODEL TUZILISHI ---
    model = Sequential()
    
    # 1-qavat
    model.add(Dense(64, input_dim=X_train.shape[1], activation='relu'))
    
    # 2-qavat
    model.add(Dense(32, activation='relu'))
    model.add(Dropout(0.2)) 
    
    # 3-qavat
    model.add(Dense(16, activation='relu'))
    
    # 4-qavat (Chiqish)
    model.add(Dense(1, activation='sigmoid'))

    # Modelni yig'ish
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    print("[*] 4. O'QITISH BOSHLANDI (Training)...")
    # O'qitish
    model.fit(X_train, y_train, epochs=5,batch_size=32, validation_data=(X_test, y_test))

    # Natijani tekshirish
    loss, accuracy = model.evaluate(X_test, y_test)
    print(f"\n[RESULT] Model Aniqligi: {accuracy*100:.2f}%")

    # Keras modelini saqlash
    model.save('models/deep_firewall.keras')
    print("[+] Model saqlandi: models/deep_firewall.keras")

if __name__ == "__main__":
    train_deep_model()
