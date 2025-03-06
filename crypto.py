import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class Crypto:
    """
    GuardCore uygulaması için şifreleme, şifre çözme ve hash işlemleri.
    Hassas veri ve yapılandırma ayarlarının güvenli şekilde saklanması için kullanılır.
    """
    
    def __init__(self, key=None, salt=None):
        """
        Kriptografi yardımcısını başlat.
        Eğer anahtar ve tuz sağlanmazsa, yeni değerler üretilir.
        
        Args:
            key: Şifreleme anahtarı (yoksa yeni üretilir)
            salt: Key türetme için kullanılan tuz (yoksa yeni üretilir)
        """
        if salt is None:
            self.salt = os.urandom(16)
        else:
            self.salt = salt if isinstance(salt, bytes) else base64.b64decode(salt)
            
        if key is None:
            self.key = self._generate_key()
        else:
            self.key = key if isinstance(key, bytes) else base64.b64decode(key)
            
        self.cipher = Fernet(self.key)
    
    def encrypt_data(self, data):
        """
        Veriyi şifrele.
        
        Args:
            data: Şifrelenecek veri (str veya bytes)
            
        Returns:
            str: Base64 formatında şifrelenmiş veri
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        encrypted = self.cipher.encrypt(data)
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_data(self, encrypted_data):
        """
        Şifrelenmiş veriyi çöz.
        
        Args:
            encrypted_data: Base64 formatında şifrelenmiş veri (str)
            
        Returns:
            str: Çözülmüş veri
        """
        if isinstance(encrypted_data, str):
            encrypted_data = base64.b64decode(encrypted_data)
            
        decrypted = self.cipher.decrypt(encrypted_data)
        return decrypted.decode('utf-8')
    
    def hash_password(self, password):
        """
        Bir paroladan güvenli bir hash oluştur.
        
        Args:
            password: Hashlenecek parola (str)
            
        Returns:
            str: Base64 formatında parola hash'i
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        
        hashed = kdf.derive(password)
        return base64.b64encode(hashed).decode('utf-8')
    
    def verify_password(self, password, hashed):
        """
        Verilen parolanın hash ile eşleşip eşleşmediğini kontrol et.
        
        Args:
            password: Kontrol edilecek parola (str)
            hashed: Karşılaştırılacak hash (str)
            
        Returns:
            bool: Eşleşme durumu
        """
        return self.hash_password(password) == hashed
    
    def _generate_key(self):
        """
        Şifreleme için rastgele bir anahtar üret.
        
        Returns:
            bytes: Rastgele üretilmiş anahtar
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        
        # Rastgele parola kullanarak anahtar türet
        random_password = os.urandom(32)
        key = base64.urlsafe_b64encode(kdf.derive(random_password))
        return key
    
    def get_key_as_string(self):
        """
        Anahtarı string olarak döndür (depolama için).
        
        Returns:
            str: Base64 formatında anahtar
        """
        return base64.b64encode(self.key).decode('utf-8')
    
    def get_salt_as_string(self):
        """
        Tuzu string olarak döndür (depolama için).
        
        Returns:
            str: Base64 formatında tuz
        """
        return base64.b64encode(self.salt).decode('utf-8')

# Yardımcı fonksiyonlar
def create_crypto():
    """
    Yeni bir kriptografi yardımcısı oluştur.
    
    Returns:
        tuple: (Crypto nesnesi, key, salt)
    """
    crypto = Crypto()
    key = crypto.get_key_as_string()
    salt = crypto.get_salt_as_string()
    
    return crypto, key, salt

def load_crypto(key, salt):
    """
    Mevcut anahtar ve tuz ile bir kriptografi yardımcısı yükle.
    
    Args:
        key: Şifreleme anahtarı (str)
        salt: Key türetme için kullanılan tuz (str)
        
    Returns:
        Crypto: Kriptografi yardımcısı
    """
    return Crypto(key, salt)