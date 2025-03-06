import logging
import os
import shutil
import time
import threading
import hashlib
import winreg
from modules.common.event import EventTypes, EventBus
from modules.common.threat import Threat
from db.repository import Repository

class AutoRepair:
    """
    Tespit edilen sistem değişikliklerini ve tehditleri otomatik olarak onaran modül.
    Önemli sistem dosyalarının değişikliklerini izler ve kritik hasarları onarır.
    """
    
    def __init__(self, settings, repository=None):
        self.settings = settings
        self.repository = repository or Repository()
        self.logger = logging.getLogger("GuardCore.AutoRepair")
        self.event_bus = EventBus()
        self.active = False
        
        # Kritik sistem dosyaları ve onların hash'leri
        self.critical_files = {}
        self.repair_thread = None
        
        # Windows'ta takip edilecek önemli registry anahtarları
        self.critical_registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services")
        ]
        
        # Registry anahtar yedekleri
        self.registry_backups = {}
        
    def start(self):
        """Otomatik onarım hizmetini başlat."""
        if self.active:
            return
            
        self.active = True
        
        # İlk başlangıçta kritik dosyaları ve registry anahtarlarını kaydet
        self._load_baseline()
        
        # Event bus'a kayıt ol
        self.event_bus.subscribe(EventTypes.THREAT_DETECTED, self._on_threat_detected)
        self.event_bus.subscribe(EventTypes.FILE_MODIFIED, self._on_file_modified)
        
        # Onarım thread'ini başlat
        self.repair_thread = threading.Thread(target=self._repair_loop, daemon=True)
        self.repair_thread.start()
        
        self.logger.info("Auto repair service started")
        
    def stop(self):
        """Otomatik onarım hizmetini durdur."""
        self.active = False
        
        # Event bus aboneliklerini iptal et
        self.event_bus.unsubscribe(EventTypes.THREAT_DETECTED, self._on_threat_detected)
        self.event_bus.unsubscribe(EventTypes.FILE_MODIFIED, self._on_file_modified)
        
        if self.repair_thread:
            self.repair_thread.join(timeout=2.0)
            self.repair_thread = None
            
        self.logger.info("Auto repair service stopped")
        
    def _load_baseline(self):
        """Kritik sistem dosyalarını ve registry anahtarlarını yükle/kaydet."""
        # Kaydedilmiş temel dosyaları yükle
        saved_baseline = self.repository.get_all('system_baseline')
        
        if saved_baseline:
            for item in saved_baseline:
                if item.get('type') == 'file':
                    self.critical_files[item.get('path')] = item.get('hash')
                elif item.get('type') == 'registry':
                    key_path = item.get('key_path')
                    values = item.get('values', {})
                    self.registry_backups[key_path] = values
                    
            self.logger.info(f"Loaded {len(self.critical_files)} critical files and {len(self.registry_backups)} registry keys from baseline")
        else:
            # Yeni temel oluştur
            self._create_baseline()
            
    def _create_baseline(self):
        """Kritik sistem dosyalarını ve registry anahtarlarını kaydeden yeni bir temel oluştur."""
        # Kritik sistem dosyalarını ekle
        critical_paths = self.settings.get('remediation.critical_files', [
            # Windows için örnek kritik dosyalar
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\drivers\etc\services"
        ])
        
        for path in critical_paths:
            if os.path.exists(path) and os.path.isfile(path):
                file_hash = self._calculate_file_hash(path)
                if file_hash:
                    self.critical_files[path] = file_hash
                    
                    # Veritabanına kaydet
                    self.repository.save('system_baseline', {
                        'type': 'file',
                        'path': path,
                        'hash': file_hash,
                        'timestamp': time.time()
                    })
        
        # Windows registry anahtarlarını yedekle
        for hkey, subkey in self.critical_registry_keys:
            try:
                key_path = f"{hkey}\\{subkey}"
                values = self._backup_registry_key(hkey, subkey)
                if values:
                    self.registry_backups[key_path] = values
                    
                    # Veritabanına kaydet
                    self.repository.save('system_baseline', {
                        'type': 'registry',
                        'key_path': key_path,
                        'values': values,
                        'timestamp': time.time()
                    })
            except Exception as e:
                self.logger.error(f"Error backing up registry key {subkey}: {e}")
                
        self.logger.info(f"Created new baseline with {len(self.critical_files)} critical files and {len(self.registry_backups)} registry keys")
        
        # Kritik sistem dosyalarının yedeğini al
        for path in self.critical_files:
            self._backup_file(path)
    
    def _backup_file(self, file_path):
        """Kritik bir sistem dosyasının yedeğini al."""
        try:
            backup_dir = self.settings.get('remediation.backup_directory', 'data/backups')
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir, exist_ok=True)
                
            filename = os.path.basename(file_path)
            backup_path = os.path.join(backup_dir, f"{filename}.bak")
            
            shutil.copy2(file_path, backup_path)
            self.logger.debug(f"Backed up {file_path} to {backup_path}")
            
            return backup_path
        except Exception as e:
            self.logger.error(f"Error backing up file {file_path}: {e}")
            return None
    
    def _backup_registry_key(self, hkey, subkey):
        """Registry anahtarının bir yedeğini al."""
        try:
            values = {}
            
            key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
            info = winreg.QueryInfoKey(key)
            
            # Tüm değerleri kaydet
            for i in range(info[1]):
                name, data, data_type = winreg.EnumValue(key, i)
                values[name] = {
                    'data': data,
                    'type': data_type
                }
                
            winreg.CloseKey(key)
            return values
        except Exception as e:
            self.logger.error(f"Error backing up registry key {subkey}: {e}")
            return None
    
    def _repair_loop(self):
        """Düzenli onarım için ana döngü."""
        check_interval = self.settings.get('remediation.check_interval_sec', 3600)  # Varsayılan 1 saat
        
        while self.active:
            try:
                # Kritik dosyaları kontrol et ve onar
                self._check_critical_files()
                
                # Registry değişikliklerini kontrol et ve onar
                self._check_registry_changes()
                
                # Bekleyen onarım görevlerini kontrol et
                self._process_repair_tasks()
                
                # Belirli aralıklarla bekle
                time.sleep(check_interval)
            except Exception as e:
                self.logger.error(f"Error in auto repair loop: {e}")
                time.sleep(300)  # Hata durumunda 5 dakika bekle
    
    def _check_critical_files(self):
        """Kritik sistem dosyalarını değişiklik için kontrol et ve gerekirse onar."""
        for file_path, original_hash in self.critical_files.items():
            if not os.path.exists(file_path):
                self.logger.warning(f"Critical file missing: {file_path}")
                self._repair_file(file_path)
                continue
                
            current_hash = self._calculate_file_hash(file_path)
            if current_hash and current_hash != original_hash:
                self.logger.warning(f"Critical file modified: {file_path}")
                self._repair_file(file_path)
    
    def _check_registry_changes(self):
        """Registry değişikliklerini kontrol et ve gerekirse onar."""
        for hkey, subkey in self.critical_registry_keys:
            key_path = f"{hkey}\\{subkey}"
            original_values = self.registry_backups.get(key_path)
            
            if not original_values:
                continue
                
            current_values = self._backup_registry_key(hkey, subkey)
            if not current_values:
                continue
                
            # Değişiklikleri kontrol et
            for name, original in original_values.items():
                if name not in current_values or current_values[name]['data'] != original['data']:
                    self.logger.warning(f"Registry value changed: {key_path}\\{name}")
                    self._repair_registry_value(hkey, subkey, name, original['data'], original['type'])
            
            # Yeni eklenmiş değerleri kontrol et
            for name in current_values:
                if name not in original_values:
                    self.logger.warning(f"New registry value added: {key_path}\\{name}")
                    self._remove_registry_value(hkey, subkey, name)
    
    def _process_repair_tasks(self):
        """Bekleyen onarım görevlerini işle."""
        repair_tasks = self.repository.query('repair_tasks', lambda x: x.get('status') == 'pending')
        
        for task in repair_tasks:
            task_id = task.get('id')
            task_type = task.get('type')
            
            try:
                if task_type == 'file_repair':
                    file_path = task.get('file_path')
                    self._repair_file(file_path)
                elif task_type == 'registry_repair':
                    hkey = task.get('hkey')
                    subkey = task.get('subkey')
                    name = task.get('name')
                    data = task.get('data')
                    data_type = task.get('data_type')
                    self._repair_registry_value(hkey, subkey, name, data, data_type)
                
                # Görevi tamamlandı olarak işaretle
                task['status'] = 'completed'
                task['completed_at'] = time.time()
                self.repository.save('repair_tasks', task)
                
                self.logger.info(f"Completed repair task: {task_id}")
            except Exception as e:
                self.logger.error(f"Error processing repair task {task_id}: {e}")
                
                # Görevi başarısız olarak işaretle
                task['status'] = 'failed'
                task['error'] = str(e)
                self.repository.save('repair_tasks', task)
    
    def _repair_file(self, file_path):
        """Değiştirilen veya silinen bir dosyayı onar."""
        try:
            # Yedekten dosyayı geri yükle
            backup_dir = self.settings.get('remediation.backup_directory', 'data/backups')
            filename = os.path.basename(file_path)
            backup_path = os.path.join(backup_dir, f"{filename}.bak")
            
            if os.path.exists(backup_path):
                # Geri yükle
                shutil.copy2(backup_path, file_path)
                self.logger.info(f"Repaired file: {file_path}")
                
                # Onarım olayı yayınla
                self.event_bus.publish(EventTypes.THREAT_REMEDIATED, {
                    'type': 'file_repaired',
                    'path': file_path,
                    'remediation_type': 'restore_from_backup'
                })
                
                return True
            else:
                self.logger.error(f"No backup found for {file_path}")
                return False
        except Exception as e:
            self.logger.error(f"Error repairing file {file_path}: {e}")
            return False
    
    def _repair_registry_value(self, hkey, subkey, name, data, data_type):
        """Değiştirilen bir registry değerini onar."""
        try:
            key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_WRITE)
            winreg.SetValueEx(key, name, 0, data_type, data)
            winreg.CloseKey(key)
            
            self.logger.info(f"Repaired registry value: {hkey}\\{subkey}\\{name}")
            
            # Onarım olayı yayınla
            self.event_bus.publish(EventTypes.THREAT_REMEDIATED, {
                'type': 'registry_repaired',
                'key_path': f"{hkey}\\{subkey}",
                'name': name,
                'remediation_type': 'restore_from_backup'
            })
            
            return True
        except Exception as e:
            self.logger.error(f"Error repairing registry value {hkey}\\{subkey}\\{name}: {e}")
            return False
    
    def _remove_registry_value(self, hkey, subkey, name):
        """Şüpheli bir registry değerini kaldır."""
        try:
            key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_WRITE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            
            self.logger.info(f"Removed suspicious registry value: {hkey}\\{subkey}\\{name}")
            
            # Onarım olayı yayınla
            self.event_bus.publish(EventTypes.THREAT_REMEDIATED, {
                'type': 'registry_removed',
                'key_path': f"{hkey}\\{subkey}",
                'name': name,
                'remediation_type': 'remove_suspicious'
            })
            
            return True
        except Exception as e:
            self.logger.error(f"Error removing registry value {hkey}\\{subkey}\\{name}: {e}")
            return False
    
    def _on_threat_detected(self, event):
        """Tehdit tespit olaylarını işle ve uygun onarımı başlat."""
        threat_type = event.get('type')
        
        # Tehdide göre onarım stratejisi belirle
        if threat_type == 'malicious_file':
            file_path = event.get('details', {}).get('file_path')
            if file_path:
                # Dosyayı karantinaya al
                self.event_bus.publish(EventTypes.QUARANTINE_OPERATION, {
                    'operation': 'quarantine_file',
                    'file_path': file_path,
                    'threat_info': event
                })
                
        elif threat_type == 'registry_modification':
            details = event.get('details', {})
            hkey = details.get('hkey')
            subkey = details.get('subkey')
            name = details.get('name')
            
            if hkey and subkey and name:
                # Registry değerini onar
                key_path = f"{hkey}\\{subkey}"
                original_values = self.registry_backups.get(key_path, {})
                
                if name in original_values:
                    original = original_values[name]
                    self._repair_registry_value(hkey, subkey, name, original['data'], original['type'])
                else:
                    self._remove_registry_value(hkey, subkey, name)
    
    def _on_file_modified(self, event):
        """Dosya değişikliği olaylarını işle ve kritik dosyalar için kontrol et."""
        file_path = event.get('path')
        
        if file_path in self.critical_files:
            current_hash = self._calculate_file_hash(file_path)
            original_hash = self.critical_files[file_path]
            
            if current_hash != original_hash:
                self.logger.warning(f"Critical file modified: {file_path}")
                
                # Dosya değişikliğini tehdit olarak raporla
                threat = Threat(
                    type="critical_file_modified",
                    name="Critical System File Modified",
                    description=f"Critical system file was modified: {file_path}",
                    severity="high",
                    details={
                        'file_path': file_path,
                        'original_hash': original_hash,
                        'current_hash': current_hash
                    },
                    detection_time=time.time(),
                    status="detected"
                )
                
                # Tehdidi veritabanına kaydet
                self.repository.save('threats', threat.to_dict())
                
                # Otomatik onarım için bir görev oluştur
                repair_task = {
                    'id': self.repository.generate_id(),
                    'type': 'file_repair',
                    'file_path': file_path,
                    'created_at': time.time(),
                    'status': 'pending'
                }
                self.repository.save('repair_tasks', repair_task)
                
                # Olay gönder
                self.event_bus.publish(EventTypes.THREAT_DETECTED, threat.to_dict())
    
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