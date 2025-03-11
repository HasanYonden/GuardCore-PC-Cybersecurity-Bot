import logging
import os
import json
import requests
import hashlib
import time
import threading
import zipfile
import shutil
import subprocess
from modules.common.event import EventTypes, EventBus
from db.repository import Repository

class UpdateManager:
    """
    Güvenlik botunun ve güvenlik veritabanının güncellemelerini yöneten modül.
    Otomatik güncellemeleri planlar, indirir ve uygular.
    """
    
    def __init__(self, settings, repository=None):
        self.settings = settings
        self.repository = repository or Repository()
        self.logger = logging.getLogger("GuardCore.UpdateManager")
        self.event_bus = EventBus()
        self.active = False
        self.update_thread = None
        
        # Güncelleme sunucusu ve uygulama bilgileri
        self.update_server = self.settings.get('update.server_url', 'https://updates.guardcore.example.com')
        self.current_version = self.settings.get('app.version', '1.0.0')
        self.application_path = self.settings.get('app.install_path', os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        
        # Güncelleme ayarları
        self.auto_update_enabled = self.settings.get('update.auto_update_enabled', True)
        self.signature_update_enabled = self.settings.get('update.signature_update_enabled', True)
        
        # Son güncelleme kontrol zamanı
        self.last_update_check = 0
        self.last_signature_update = 0
        
    def start(self):
        """Güncelleme hizmetini başlat."""
        if self.active:
            return
            
        self.active = True
        
        # Son güncelleme zamanlarını veritabanından yükle
        update_info = self.repository.get_by_id('system_info', 'update_timestamps')
        if update_info:
            self.last_update_check = update_info.get('last_update_check', 0)
            self.last_signature_update = update_info.get('last_signature_update', 0)
        
        # Güncelleme thread'ini başlat
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        
        self.logger.info("Update manager service started")
        
    def stop(self):
        """Güncelleme hizmetini durdur."""
        self.active = False
        
        if self.update_thread:
            self.update_thread.join(timeout=2.0)
            self.update_thread = None
            
        self.logger.info("Update manager service stopped")
        
    def check_for_updates(self, force=False):
        """Yazılım güncellemelerini kontrol et."""
        if not self.active and not force:
            return None
            
        try:
            # Son kontrol zamanını güncelle
            self.last_update_check = time.time()
            self._save_update_timestamps()
            
            # Güncelleme sunucusundan bilgi al
            update_url = f"{self.update_server}/api/check-update?version={self.current_version}"
            response = requests.get(update_url, timeout=10)
            
            if response.status_code != 200:
                self.logger.error(f"Failed to check updates: {response.status_code}")
                return None
                
            update_info = response.json()
            
            # Güncelleme var mı kontrol et
            if not update_info.get('update_available', False):
                self.logger.info("No updates available")
                return None
                
            # Güncelleme bilgilerini döndür
            return {
                'version': update_info.get('version'),
                'release_date': update_info.get('release_date'),
                'size': update_info.get('size'),
                'download_url': update_info.get('download_url'),
                'release_notes': update_info.get('release_notes'),
                'critical': update_info.get('critical', False)
            }
        except Exception as e:
            self.logger.error(f"Error checking for updates: {e}")
            return None
    
    def update_signatures(self, force=False):
        """Tehdit imza veritabanını güncelle."""
        if not self.active and not force:
            return False
            
        try:
            # Son kontrol zamanını güncelle
            self.last_signature_update = time.time()
            self._save_update_timestamps()
            
            # İmza güncelleme sunucusundan bilgi al
            signature_url = f"{self.update_server}/api/signatures/latest"
            response = requests.get(signature_url, timeout=10)
            
            if response.status_code != 200:
                self.logger.error(f"Failed to check signature updates: {response.status_code}")
                return False
                
            signature_info = response.json()
            
            # İmza dizini
            signature_dir = self.settings.get('protection.signature_path', 'data/signatures')
            os.makedirs(signature_dir, exist_ok=True)
            
            # Yerel imza sürümünü kontrol et
            local_version_file = os.path.join(signature_dir, 'version.json')
            local_version = None
            
            if os.path.exists(local_version_file):
                with open(local_version_file, 'r') as f:
                    local_info = json.load(f)
                    local_version = local_info.get('version')
            
            # Güncelleme gerekiyor mu?
            remote_version = signature_info.get('version')
            if local_version and remote_version <= local_version and not force:
                self.logger.info(f"Signature database is up to date (version {local_version})")
                return True
                
            # İmza dosyasını indir
            download_url = signature_info.get('download_url')
            if not download_url:
                self.logger.error("No download URL provided for signature update")
                return False
                
            # İndirme yolunu oluştur
            temp_dir = os.path.join(signature_dir, 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            
            download_path = os.path.join(temp_dir, 'signatures.zip')
            
            # İmza dosyasını indir
            self.logger.info(f"Downloading signature database v{remote_version} from {download_url}")
            self._download_file(download_url, download_path)
            
            # Hash'i doğrula
            expected_hash = signature_info.get('hash')
            if expected_hash:
                file_hash = self._calculate_file_hash(download_path)
                if file_hash != expected_hash:
                    self.logger.error(f"Signature file hash mismatch: {file_hash} != {expected_hash}")
                    return False
            
            # İndirilen dosyayı aç
            with zipfile.ZipFile(download_path, 'r') as zip_ref:
                zip_ref.extractall(signature_dir)
                
            # Version dosyasını güncelle
            with open(local_version_file, 'w') as f:
                json.dump({
                    'version': remote_version,
                    'update_date': time.time()
                }, f)
            
            # Geçici dosyaları temizle
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                
            self.logger.info(f"Successfully updated signature database to version {remote_version}")
            
            # Güncelleme olayı yayınla
            self.event_bus.publish(EventTypes.SYSTEM_OPERATION, {
                'operation': 'signatures_updated',
                'old_version': local_version,
                'new_version': remote_version
            })
            
            return True
        except Exception as e:
            self.logger.error(f"Error updating signatures: {e}")
            return False
    
    def download_update(self, update_info):
        """Yazılım güncellemesini indir."""
        try:
            # Güncelleme dizini
            update_dir = os.path.join(self.application_path, 'updates')
            os.makedirs(update_dir, exist_ok=True)
            
            version = update_info.get('version')
            download_url = update_info.get('download_url')
            
            if not download_url:
                self.logger.error("No download URL provided for update")
                return None
                
            download_path = os.path.join(update_dir, f"guardcore_update_{version}.zip")
            
            # Güncelleme dosyasını indir
            self.logger.info(f"Downloading update v{version} from {download_url}")
            self._download_file(download_url, download_path)
            
            # Hash'i doğrula
            expected_hash = update_info.get('hash')
            if expected_hash:
                file_hash = self._calculate_file_hash(download_path)
                if file_hash != expected_hash:
                    self.logger.error(f"Update file hash mismatch: {file_hash} != {expected_hash}")
                    return None
            
            # İndirme bilgisini kaydet
            update_record = {
                'id': self.repository.generate_id(),
                'version': version,
                'download_path': download_path,
                'download_date': time.time(),
                'status': 'downloaded',
                'info': update_info
            }
            self.repository.save('updates', update_record)
            
            self.logger.info(f"Successfully downloaded update v{version} to {download_path}")
            
            return download_path
        except Exception as e:
            self.logger.error(f"Error downloading update: {e}")
            return None
    
    def apply_update(self, update_path, version):
        """İndirilen güncellemeyi uygula."""
        try:
            # Geçici dizini oluştur
            temp_dir = os.path.join(self.application_path, 'temp_update')
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                
            os.makedirs(temp_dir, exist_ok=True)
            
            # Güncelleme dosyasını aç
            with zipfile.ZipFile(update_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
                
            # Güncelleme betiğini çalıştır
            update_script = os.path.join(temp_dir, 'update.bat' if os.name == 'nt' else 'update.sh')
            
            if not os.path.exists(update_script):
                self.logger.error(f"Update script not found: {update_script}")
                return False
                
            # Mevcut işlemi durdurmak için bir olay yayınla
            self.event_bus.publish(EventTypes.SYSTEM_OPERATION, {
                'operation': 'update_starting',
                'version': version
            })
            
            # GuardCore servisini kapat ve güncelleme betiğini başlat
            self.logger.info(f"Starting update process to version {version}")
            
            if os.name == 'nt':
                # Windows'ta güncelleme betiğini başlat
                subprocess.Popen(['cmd.exe', '/c', update_script, self.application_path, version])
            else:
                # Linux/macOS'ta güncelleme betiğini başlat
                subprocess.Popen(['bash', update_script, self.application_path, version])
                
            # Program kendini sonlandıracak - bu noktadan sonraki kodlar çalışmayabilir
            return True
        except Exception as e:
            self.logger.error(f"Error applying update: {e}")
            return False
    
    def _update_loop(self):
        """Güncelleme kontrolü için ana döngü."""
        update_interval = self.settings.get('update.check_interval_hours', 24) * 3600
        signature_interval = self.settings.get('update.signature_check_interval_hours', 6) * 3600
        
        while self.active:
            try:
                current_time = time.time()
                
                # Yazılım güncellemelerini kontrol et
                if self.auto_update_enabled and (current_time - self.last_update_check > update_interval):
                    update_info = self.check_for_updates()
                    
                    if update_info:
                        version = update_info.get('version')
                        self.logger.info(f"New update available: v{version}")
                        
                        # Kritik güncellemeler için otomatik güncelleme
                        if update_info.get('critical', False) and self.auto_update_enabled:
                            self.logger.info(f"Critical update v{version} will be automatically installed")
                            download_path = self.download_update(update_info)
                            
                            if download_path:
                                # Otomatik güncelleme başlayacak
                                self.apply_update(download_path, version)
                        else:
                            # Kullanıcıya bildirim gönder
                            self.event_bus.publish(EventTypes.UI_NOTIFICATION, {
                                'type': 'update_available',
                                'title': f"GuardCore Update Available",
                                'message': f"Version {version} is available for installation",
                                'update_info': update_info
                            })
                
                # İmza güncellemelerini kontrol et
                if self.signature_update_enabled and (current_time - self.last_signature_update > signature_interval):
                    self.update_signatures()
                
                # 30 dakika bekle
                time.sleep(1800)
            except Exception as e:
                self.logger.error(f"Error in update loop: {e}")
                time.sleep(3600)  # Hata durumunda 1 saat bekle
    
    def _download_file(self, url, destination):
        """Bir dosyayı URL'den indir ve belirtilen hedef konuma kaydet."""
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(destination, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not self.active:
                        break
                        
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # İndirme ilerleme olayı
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            if progress % 10 < 0.1:  # Her %10'da bir rapor
                                self.logger.debug(f"Download progress: {progress:.1f}%")
            
            return True
        except Exception as e:
            self.logger.error(f"Error downloading file from {url}: {e}")
            
            # Yarım kalmış indirmeyi temizle
            if os.path.exists(destination):
                os.remove(destination)
                
            return False
    
    def _calculate_file_hash(self, file_path):
        """Bir dosyanın SHA-256 hash'ini hesapla."""
        try:
            sha256_hash = hashlib.sha256()
            
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
                    
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return None
    
    def _save_update_timestamps(self):
        """Güncelleme zaman damgalarını veritabanına kaydet."""
        self.repository.save('system_info', {
            'id': 'update_timestamps',
            'last_update_check': self.last_update_check,
            'last_signature_update': self.last_signature_update,
            'current_version': self.current_version
        })