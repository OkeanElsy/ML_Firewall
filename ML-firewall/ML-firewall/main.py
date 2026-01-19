# main.py
import sys
import joblib
import numpy as np
import os
import warnings
warnings.filterwarnings("ignore")

# Agar faqat aynan shu xabarni o'chirmoqchi bo'lsangiz:
warnings.filterwarnings("ignore", message="X does not have valid feature names")
# ... keyin boshqa importlar (import sys, import joblib va h.k.)

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' 
from tensorflow.keras.models import load_model
from scapy.all import sniff, IP
from src.features import extract_features
# Windows/Linux mosligi uchun
try:
    from src.blocker import block_ip
except ImportError:
    def block_ip(ip): print(f"   [BLOCKED] {ip} manzili bloklandi!")

print("==========================================")
print("[*] TIZIM YUKLANMOQDA (Deep Learning)...")

try:
    # 1. Neyron tarmoqni yuklash
    model = load_model('/home/okean/ML-firewall/src/models/deep_firewall.keras')
    
    # 2. Yordamchi vositalarni yuklash
    scaler = joblib.load('/home/okean/ML-firewall/models/scaler.pkl')
    le_proto = joblib.load('/home/okean/ML-firewall/models/proto_encoder.pkl')
    
    print("[+] Model va Scaler muvaffaqiyatli yuklandi.")
    print("[+] AI Firewall ishga tushdi...")
    print("==========================================")

except Exception as e:
    print(f"[!] Xatolik: {e}")
    print("Avval 'python src/train_deep.py' ni ishga tushiring!")
    sys.exit()

def packet_callback(packet):
    # Xususiyatlarni olish
    raw_features = extract_features(packet)
    
    if raw_features:
        # Ro'yxatdan ajratib olish
        proto_str = raw_features[0]
        numeric_features = raw_features[1:] # Qolgan hammasi raqam
        
        # 1. Protokolni raqamga o'girish
        try:
            proto_encoded = le_proto.transform([proto_str])[0]
        except:
            # Noma'lum protokol kelsa, shunchaki o'tkazib yuboramiz
            return

        # 2. To'liq vektor yasash
        # [protocol, src_bytes, dst_bytes, count, srv_count, same_srv, diff_srv]
        final_vector = [proto_encoded] + numeric_features
        
        # 3. Scaling (Masshtablash) - JUDI MUHIM!
        # Modelga berishdan oldin massivni 2D qilish kerak: [[...]]
        features_scaled = scaler.transform([final_vector])
        
        # 4. BASHORAT (Prediction)
        # Neyron tarmoq 0 dan 1 gacha son qaytaradi (Ehtimollik)
        prediction_prob = model.predict(features_scaled, verbose=0)[0][0]
        
        src_ip = packet[IP].src
        
        # Agar ehtimollik 50% dan yuqori bo'lsa -> HUJUM
        # Siz bu chegarani 0.8 (80%) qilib o'zgartirishingiz mumkin
        threshold = 0.5
        
        if prediction_prob > threshold:
            confidence = prediction_prob * 100
            print(f"[!!!] HUJUM ANIQLANDI ({confidence:.2f}%) -> {src_ip} | Proto: {proto_str}")
            block_ip(src_ip)
        else:
            # Normal trafikni konsolga chiqarish shart emas
            pass

if __name__ == "__main__":
    try:
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[!] Dastur to'xtatildi.")

