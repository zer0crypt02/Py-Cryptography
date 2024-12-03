from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

# Şifreleme fonksiyonu
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    
    # Şifreli veriyi base64 formatına çevir
    nonce = base64.b64encode(cipher.nonce).decode('utf-8')
    ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    tag = base64.b64encode(tag).decode('utf-8')

    return nonce, ciphertext, tag

# Dosya kaydetme fonksiyonu
def save_encrypted_data(nonce, ciphertext, tag):
    # Kullanıcının masaüstü dizin yolunu al
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop", "Cryptography.txt")
    
    # Şifreli veriyi dosyaya kaydet
    with open(desktop_path, 'w') as file:
        file.write(f"Nonce: {nonce}\n")
        file.write(f"Ciphertext: {ciphertext}\n")
        file.write(f"Tag: {tag}\n")
    print(f"Şifreli dosya Desktop'a kaydedildi: {desktop_path}")

# Ana fonksiyon
def main():
    # Kullanıcıdan metin girişi al
    text = input("Bir metin girin: ")

    # 16 byte uzunluğunda rastgele bir şifreleme anahtarı oluştur
    key = get_random_bytes(16)

    # Şifreleme işlemi
    nonce, ciphertext, tag = encrypt_data(text, key)

    # Şifreli veriyi dosyaya kaydet
    save_encrypted_data(nonce, ciphertext, tag)

if __name__ == "__main__":
    main()
