# src/features.py
from scapy.all import IP, TCP, UDP, ICMP

def extract_features(packet):
    """
    Qaytaradi: [protocol_str, src_bytes, dst_bytes, count, srv_count, same_srv_rate, diff_srv_rate]
    Eslatma: Scapy bitta paketni ko'radi, shuning uchun statistikalar (count, rate) 
    uchun taxminiy qiymat beramiz yoki kesh ishlatish kerak bo'ladi.
    """
    if IP in packet:
        # 1. Protokol
        proto_str = "tcp" # Default
        if TCP in packet: proto_str = "tcp"
        elif UDP in packet: proto_str = "udp"
        elif ICMP in packet: proto_str = "icmp"
        
        # 2. Hajmlar
        src_bytes = len(packet)
        dst_bytes = 0 # Javob paketi yo'q, shuning uchun 0 deb turamiz
        
        # 3. Statistika (Bularni real hisoblash uchun alohida xotira kerak)
        # Hozircha model ishlashi uchun o'rtacha xavfsiz qiymatlar beramiz:
        count = 1 
        srv_count = 1
        same_srv_rate = 1.0
        diff_srv_rate = 0.0
        
        return [proto_str, src_bytes, dst_bytes, count, srv_count, same_srv_rate, diff_srv_rate]
    
    return None