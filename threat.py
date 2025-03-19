#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GuardCore Tehdit Modeli
-----------------------
Bu modül, tehditleri tanımlayan ve kategorize eden sınıfları içerir.
Sistem tarafından tespit edilen tüm tehditler bu yapıları kullanır.

Yazarlar: GuardCore Dev Team
Lisans: MIT
Versiyon: 0.1.0
"""

import uuid
import time
import enum
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field


class ThreatSeverity(enum.Enum):
    """Tehdit önem derecesini tanımlayan enum sınıfı"""
    
    UNKNOWN = 0    # Bilinmeyen/Belirlenemeyen
    LOW = 10       # Düşük risk
    MEDIUM = 20    # Orta risk
    HIGH = 30      # Yüksek risk
    CRITICAL = 40  # Kritik risk


class ThreatCategory(enum.Enum):
    """Tehdit kategorilerini tanımlayan enum sınıfı"""
    
    # Zararlı yazılım kategorileri
    MALWARE = "malware"
    VIRUS = "malware.virus"
    TROJAN = "malware.trojan"
    RANSOMWARE = "malware.ransomware"
    SPYWARE = "malware.spyware"
    ADWARE = "malware.adware"
    WORM = "malware.worm"
    ROOTKIT = "malware.rootkit"
    KEYLOGGER = "malware.keylogger"
    
    # Ağ tehditleri
    NETWORK = "network"
    INTRUSION = "network.intrusion"
    PORT_SCAN = "network.port_scan"
    PHISHING = "network.phishing"
    SUSPICIOUS_CONNECTION = "network.suspicious_connection"
    
    # Web tehditleri
    WEB = "web"
    MALICIOUS_URL = "web.malicious_url"
    BROWSER_EXPLOIT = "web.browser_exploit"
    
    # Sistem tehditleri
    SYSTEM = "system"
    UNAUTHORIZED_ACCESS = "system.unauthorized_access"
    PRIVILEGE_ESCALATION = "system.privilege_escalation"
    SUSPICIOUS_PROCESS = "system.suspicious_process"
    
    # Yapılandırma tehditleri
    CONFIG = "config"
    VULNERABILITY = "config.vulnerability"
    MISCONFIGURATION = "config.misconfiguration"
    
    # Diğer tehditler
    PUA = "pua"  # Potansiyel istenmeyen uygulama
    UNKNOWN = "unknown"


class ThreatStatus(enum.Enum):
    """Tehdit durumunu tanımlayan enum sınıfı"""
    
    DETECTED = "detected"           # Tespit edildi
    ANALYZING = "analyzing"         # Analiz ediliyor
    BLOCKED = "blocked"             # Engellendi
    QUARANTINED = "quarantined"     # Karantinaya alındı
    REMOVED = "removed"             # Kaldırıldı
    ALLOWED = "allowed"             # İzin verildi (kullanıcı tarafından)
    RESTORED = "restored"           # Karantinadan geri yüklendi
    UNRESOLVED = "unresolved"       # Çözülmedi
    FALSE_POSITIVE = "false_positive"  # Yanlış algılama


@dataclass
class Threat:
    """
    Tespit edilen tehditleri tanımlayan veri sınıfı.
    """
    
    name: str                           # Tehdit adı
    category: ThreatCategory            # Tehdit kategorisi
    severity: ThreatSeverity            # Tehdit önemi
    source: str                         # Tehdidi tespit eden kaynak (modül)
    details: Dict[str, Any] = field(default_factory=dict)  # Tehdit detayları
    
    # Otomatik oluşturulan alanlar
    id: str = field(default_factory=lambda: str(uuid.uuid4()))  # Tehdit ID'si
    detection_time: float = field(default_factory=time.time)  # Tespit zamanı
    status: ThreatStatus = ThreatStatus.DETECTED  # Tehdidin durumu
    affected_files: List[str] = field(default_factory=list)  # Etkilenen dosyalar
    affected_processes: List[int] = field(default_factory=list)  # Etkilenen işlemler
    tags: Set[str] = field(default_factory=set)  # Etiketler
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Tehdit nesnesini sözlük formatına dönüştürür
        
        Returns:
            Dict[str, Any]: Tehdit verilerini içeren sözlük
        """
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity.value,
            "source": self.source,
            "details": self.details,
            "detection_time": self.detection_time,
            "status": self.status.value,
            "affected_files": self.affected_files,
            "affected_processes": self.affected_processes,
            "tags": list(self.tags)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Threat':
        """
        Sözlükten Threat nesnesi oluşturur
        
        Args:
            data (Dict[str, Any]): Tehdit verilerini içeren sözlük
            
        Returns:
            Threat: Oluşturulan tehdit nesnesi
        """
        # Kategorileri ve durumları enum'a dönüştür
        category = data.get("category")
        if isinstance(category, str):
            category = ThreatCategory(category)
        
        severity = data.get("severity")
        if isinstance(severity, (int, str)):
            severity = ThreatSeverity(severity)
        
        status = data.get("status")
        if isinstance(status, str):
            status = ThreatStatus(status)
        
        # Threat nesnesini oluştur
        threat = cls(
            name=data["name"],
            category=category,
            severity=severity,
            source=data["source"],
            details=data.get("details", {})
        )
        
        # Diğer alanları ayarla
        threat.id = data.get("id", threat.id)
        threat.detection_time = data.get("detection_time", threat.detection_time)
        threat.status = status or threat.status
        threat.affected_files = data.get("affected_files", [])
        threat.affected_processes = data.get("affected_processes", [])
        threat.tags = set(data.get("tags", []))
        
        return threat
    
    def update_status(self, new_status: ThreatStatus) -> None:
        """
        Tehdit durumunu günceller
        
        Args:
            new_status (ThreatStatus): Yeni durum
        """
        self.status = new_status
    
    def add_affected_file(self, file_path: str) -> None:
        """
        Etkilenen dosya listesine bir dosya ekler
        
        Args:
            file_path (str): Etkilenen dosya yolu
        """
        if file_path not in self.affected_files:
            self.affected_files.append(file_path)
    
    def add_affected_process(self, process_id: int) -> None:
        """
        Etkilenen işlem listesine bir işlem ekler
        
        Args:
            process_id (int): Etkilenen işlem ID'si
        """
        if process_id not in self.affected_processes:
            self.affected_processes.append(process_id)
    
    def add_tag(self, tag: str) -> None:
        """
        Tehdit etiketlerine bir etiket ekler
        
        Args:
            tag (str): Eklenecek etiket
        """
        self.tags.add(tag)
    
    def get_description(self) -> str:
        """
        Tehdit açıklamasını döndürür
        
        Returns:
            str: Tehdit açıklaması
        """
        return self.details.get("description", "Tehdit hakkında açıklama bulunmuyor.")
    
    def get_recommended_actions(self) -> List[str]:
        """
        Önerilen eylemleri döndürür
        
        Returns:
            List[str]: Önerilen eylemler listesi
        """
        return self.details.get("recommended_actions", [])
    
    def is_active(self) -> bool:
        """
        Tehdidin hala aktif olup olmadığını kontrol eder
        
        Returns:
            bool: Tehdit aktif mi?
        """
        inactive_states = [
            ThreatStatus.REMOVED,
            ThreatStatus.QUARANTINED,
            ThreatStatus.ALLOWED,
            ThreatStatus.FALSE_POSITIVE
        ]
        return self.status not in inactive_states
    
    def __str__(self) -> str:
        """Threat nesnesinin string gösterimi"""
        return f"Threat(id={self.id}, name={self.name}, category={self.category.name}, severity={self.severity.name}, status={self.status.name})"


def create_threat_from_detection(name: str, category: ThreatCategory, 
                               severity: ThreatSeverity, source: str,
                               details: Dict[str, Any] = None) -> Threat:
    """
    Tespit bilgilerinden yeni bir tehdit nesnesi oluşturur
    
    Args:
        name (str): Tehdit adı
        category (ThreatCategory): Tehdit kategorisi
        severity (ThreatSeverity): Tehdit önemi
        source (str): Tehdidi tespit eden kaynak
        details (Dict[str, Any], optional): Tehdit detayları
        
    Returns:
        Threat: Oluşturulan tehdit nesnesi
    """
    return Threat(
        name=name,
        category=category,
        severity=severity,
        source=source,
        details=details or {}
    )