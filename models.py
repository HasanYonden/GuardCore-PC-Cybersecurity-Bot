import time
from enum import Enum
import uuid
import json

class BaseModel:
    """
    Tüm veritabanı modelleri için temel sınıf.
    """
    
    def __init__(self, id=None, **kwargs):
        self.id = id or str(uuid.uuid4())
        self.created_at = kwargs.get('created_at', time.time())
        self.updated_at = kwargs.get('updated_at', time.time())
        
    def to_dict(self):
        """Objeyi sözlük olarak döndür."""
        return {
            'id': self.id,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
        
    @classmethod
    def from_dict(cls, data):
        """Sözlükten bir model nesnesi oluştur."""
        if not data:
            return None
            
        return cls(**data)

class ThreatModel(BaseModel):
    """
    Tespit edilen tehditleri temsil eder.
    """
    
    class Severity(str, Enum):
        LOW = 'low'
        MEDIUM = 'medium'
        HIGH = 'high'
        CRITICAL = 'critical'
    
    class Status(str, Enum):
        DETECTED = 'detected'
        ANALYZING = 'analyzing'
        BLOCKED = 'blocked'
        QUARANTINED = 'quarantined'
        CLEANED = 'cleaned'
        IGNORED = 'ignored'
        FALSE_POSITIVE = 'false_positive'
    
    def __init__(self, id=None, **kwargs):
        super().__init__(id, **kwargs)
        self.type = kwargs.get('type', '')
        self.name = kwargs.get('name', '')
        self.description = kwargs.get('description', '')
        self.severity = kwargs.get('severity', self.Severity.MEDIUM)
        self.status = kwargs.get('status', self.Status.DETECTED)
        self.detection_time = kwargs.get('detection_time', time.time())
        self.details = kwargs.get('details', {})
        self.update_history = kwargs.get('update_history', [])
        
    def to_dict(self):
        result = super().to_dict()
        result.update({
            'type': self.type,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'status': self.status,
            'detection_time': self.detection_time,
            'details': self.details,
            'update_history': self.update_history
        })
        return result
        
    def update_status(self, new_status, comment=None):
        """Tehdit durumunu güncelle ve güncellemeleri takip et."""
        old_status = self.status
        self.status = new_status
        self.updated_at = time.time()
        
        self.update_history.append({
            'timestamp': time.time(),
            'old_status': old_status,
            'new_status': new_status,
            'comment': comment or f"Status changed from {old_status} to {new_status}"
        })

class ScanResultModel(BaseModel):
    """
    Güvenlik taraması sonuçlarını temsil eder.
    """
    
    class ScanType(str, Enum):
        QUICK = 'quick'
        FULL = 'full'
        CUSTOM = 'custom'
    
    class Status(str, Enum):
        PENDING = 'pending'
        RUNNING = 'running'
        COMPLETED = 'completed'
        CANCELLED = 'cancelled'
        FAILED = 'failed'
    
    def __init__(self, id=None, **kwargs):
        super().__init__(id, **kwargs)
        self.type = kwargs.get('type', self.ScanType.QUICK)
        self.start_time = kwargs.get('start_time', time.time())
        self.end_time = kwargs.get('end_time', None)
        self.status = kwargs.get('status', self.Status.PENDING)
        self.paths = kwargs.get('paths', [])
        self.total_files = kwargs.get('total_files', 0)
        self.scanned_files = kwargs.get('scanned_files', 0)
        self.infected_files = kwargs.get('infected_files', 0)
        self.skipped_files = kwargs.get('skipped_files', 0)
        self.threats = kwargs.get('threats', [])
        self.error = kwargs.get('error', None)
        
    def to_dict(self):
        result = super().to_dict()
        result.update({
            'type': self.type,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'status': self.status,
            'paths': self.paths,
            'total_files': self.total_files,
            'scanned_files': self.scanned_files,
            'infected_files': self.infected_files,
            'skipped_files': self.skipped_files,
            'threats': self.threats,
            'error': self.error
        })
        return result
        
    def update_counts(self, total=None, scanned=None, infected=None, skipped=None):
        """Tarama sayılarını güncelle."""
        if total is not None:
            self.total_files = total
        if scanned is not None:
            self.scanned_files = scanned
        if infected is not None:
            self.infected_files = infected
        if skipped is not None:
            self.skipped_files = skipped
            
        self.updated_at = time.time()
    
    def add_threat(self, threat):
        """Tarama sonucuna bir tehdit ekle."""
        if isinstance(threat, dict):
            self.threats.append(threat)
        else:
            self.threats.append(threat.to_dict())
            
        self.infected_files = len(self.threats)
        self.updated_at = time.time()
    
    def complete(self, status=Status.COMPLETED, error=None):
        """Taramayı tamamlandı olarak işaretle."""
        self.status = status
        self.end_time = time.time()
        self.error = error
        self.updated_at = time.time()

class QuarantineItemModel(BaseModel):
    """
    Karantinaya alınan dosyaları temsil eder.
    """
    
    def __init__(self, id=None, **kwargs):
        super().__init__(id, **kwargs)
        self.original_path = kwargs.get('original_path', '')
        self.original_name = kwargs.get('original_name', '')
        self.quarantine_date = kwargs.get('quarantine_date', time.time())
        self.file_size = kwargs.get('file_size', 0)
        self.file_hash = kwargs.get('file_hash', '')
        self.threat_info = kwargs.get('threat_info', {})
        self.restored = kwargs.get('restored', False)
        self.restore_date = kwargs.get('restore_date', None)
        self.deleted = kwargs.get('deleted', False)
        self.delete_date = kwargs.get('delete_date', None)
        
    def to_dict(self):
        result = super().to_dict()
        result.update({
            'original_path': self.original_path,
            'original_name': self.original_name,
            'quarantine_date': self.quarantine_date,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'threat_info': self.threat_info,
            'restored': self.restored,
            'restore_date': self.restore_date,
            'deleted': self.deleted,
            'delete_date': self.delete_date
        })
        return result
    
    def mark_restored(self, restore_path=None):
        """Dosyayı geri yüklenmiş olarak işaretle."""
        self.restored = True
        self.restore_date = time.time()
        if restore_path:
            self.restore_path = restore_path
        self.updated_at = time.time()
    
    def mark_deleted(self):
        """Dosyayı silinmiş olarak işaretle."""
        self.deleted = True
        self.delete_date = time.time()
        self.updated_at = time.time()

class SystemBaselineModel(BaseModel):
    """
    Sistem temel alınan durumunu temsil eder.
    """
    
    class BaselineType(str, Enum):
        FILE = 'file'
        REGISTRY = 'registry'
        PROCESS = 'process'
        NETWORK = 'network'
        SYSTEM = 'system'
    
    def __init__(self, id=None, **kwargs):
        super().__init__(id, **kwargs)
        self.type = kwargs.get('type', self.BaselineType.FILE)
        self.path = kwargs.get('path', '')
        self.hash = kwargs.get('hash', '')
        self.key_path = kwargs.get('key_path', '')
        self.values = kwargs.get('values', {})
        self.timestamp = kwargs.get('timestamp', time.time())
        self.data = kwargs.get('data', {})
        
    def to_dict(self):
        result = super().to_dict()
        result.update({
            'type': self.type,
            'path': self.path,
            'hash': self.hash,
            'key_path': self.key_path,
            'values': self.values,
            'timestamp': self.timestamp,
            'data': self.data
        })
        return result