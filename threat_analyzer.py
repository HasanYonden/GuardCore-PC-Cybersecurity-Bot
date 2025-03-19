#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GuardCore Tehdit Analiz Motoru
-----------------------------
Bu modül, olayları analiz ederek potansiyel tehditleri tespit eder.
Güvenlik olaylarını değerlendirip tehdit skorlaması yapan mantık bulunur.

Yazarlar: GuardCore Dev Team
Lisans: MIT
Versiyon: 0.1.0
"""

import os
import re
import time
import json
import logging
import threading
from typing import Dict, List, Any, Optional, Set, Tuple

from guardcore.modules.common.event import Event, EventType, EventSeverity
from guardcore.modules.common.threat import (
    Threat, ThreatCategory, ThreatSeverity, ThreatStatus,
    create_threat_from_detection
)


class ThreatAnalyzer:
    """
    Tehdit analiz motoru.
    Olayları analiz ederek tehditleri tespit eder.
    """
    
    def __init__(self, settings):
        """
        ThreatAnalyzer sınıfını başlatır.
        
        Args:
            settings: Yapılandırma ayarları
        """
        self.logger = logging.getLogger(__name__)
        self.settings = settings
        
        # Analiz durumu
        self.is_running = False
        
        # İlişkili olay belleği
        self.event_memory = {}  # {event_type: deque(max_len=100)}
        self.memory_lock = threading.RLock()
        
        # İmza veritabanları
        self.signatures = {}
        self.ioc_patterns = {}
        
        # Tehdit puanlama
        self.threat_scores = {}  # {entity: score}
        
        # İstatistikler
        self.stats = {
            "events_analyzed": 0,
            "threats_detected": 0,
            "false_positives": 0,
            "last_detection_time": 0
        }
        
        self.logger.info("Tehdit analiz motoru hazırlandı")
    
    def start(self):
        """Analiz motorunu başlatır"""
        if self.is_running:
            self.logger.warning("Tehdit analiz motoru zaten çalışıyor")
            return
        
        try:
            # İmza veritabanını yükle
            self._load_signatures()
            
            # İlk çalıştırma işlemleri
            self.is_running = True
            
            self.logger.info("Tehdit analiz motoru başlatıldı")
            
        except Exception as e:
            self.logger.error(f"Tehdit analiz motoru başlatılırken hata: {e}", exc_info=True)
            self.is_running = False
    
    def stop(self):
        """Analiz motorunu durdurur"""
        if not self.is_running:
            return
        
        try:
            # Kaynakları temizle
            self.is_running = False
            
            self.logger.info("Tehdit analiz motoru durduruldu")
            
        except Exception as e:
            self.logger.error(f"Tehdit analiz motoru durdurulurken hata: {e}")
    
    def analyze_event(self, event: Event) -> Optional[Threat]:
        """
        Bir olayı analiz eder ve tehdit tespit edilirse döndürür.
        
        Args:
            event (Event): Analiz edilecek olay
            
        Returns:
            Optional[Threat]: Tespit edilen tehdit veya None
        """
        if not self.is_running:
            self.logger.warning("Tehdit analiz motoru çalışmıyor")
            return None
        
        if not event.needs_analysis:
            return None
        
        try:
            # İstatistikleri güncelle
            self.stats["events_analyzed"] += 1
            
            # Olay hafızasına ekle
            self._add_to_memory(event)
            
            # Olay tipine göre analiz fonksiyonunu seç
            if event.type == EventType.FILE_CREATED or event.type == EventType.FILE_MODIFIED:
                return self._analyze_file_event(event)
            
            elif event.type == EventType.PROCESS_STARTED:
                return self._analyze_process_event(event)
            
            elif event.type == EventType.NETWORK_CONNECTION:
                return self._analyze_network_event(event)
            
            elif event.type == EventType.NETWORK_ALERT:
                return self._analyze_network_alert(event)
            
            elif event.type == EventType.SYSTEM_CHANGE:
                return self._analyze_system_change(event)
            
            # Diğer olaylar için şimdilik tehdit tespit edilmedi
            return None
            
        except Exception as e:
            self.logger.error(f"Olay analiz edilirken hata: {e}", exc_info=True)
            return None
    
    def evaluate_ioc(self, ioc_type: str, value: str) -> Tuple[bool, float, str]:
        """
        Indicator of Compromise (IoC) değerini değerlendirir.
        
        Args:
            ioc_type (str): IoC tipi (ip, domain, file_hash, vb.)
            value (str): Değerlendirilecek değer
            
        Returns:
            Tuple[bool, float, str]: (Tehdit mi?, Tehdit skoru, Açıklama)
        """
        # IoC tipine göre ilgili değerlendirme fonksiyonunu çağır
        if ioc_type == "ip":
            return self._evaluate_ip_ioc(value)
        
        elif ioc_type == "domain":
            return self._evaluate_domain_ioc(value)
        
        elif ioc_type == "file_hash":
            return self._evaluate_hash_ioc(value)
        
        elif ioc_type == "url":
            return self._evaluate_url_ioc(value)
        
        # Bilinmeyen IoC tipi
        return False, 0.0, "Bilinmeyen IoC tipi"
    
    def get_threat_score(self, entity: str) -> float:
        """
        Belirli bir varlık için tehdit puanını döndürür.
        
        Args:
            entity (str): Varlık (IP, dosya yolu, işlem, vb.)
            
        Returns:
            float: Tehdit puanı (0.0 - 1.0 arası)
        """
        return self.threat_scores.get(entity, 0.0)
    
    def update_threat_score(self, entity: str, score_delta: float) -> float:
        """
        Belirli bir varlık için tehdit puanını günceller.
        
        Args:
            entity (str): Varlık (IP, dosya yolu, işlem, vb.)
            score_delta (float): Puan değişimi
            
        Returns:
            float: Güncellenen tehdit puanı
        """
        current_score = self.threat_scores.get(entity, 0.0)
        new_score = max(0.0, min(1.0, current_score + score_delta))
        self.threat_scores[entity] = new_score
        return new_score
    
    def classify_severity(self, score: float) -> ThreatSeverity:
        """
        Tehdit puanını önem derecesine dönüştürür.
        
        Args:
            score (float): Tehdit puanı (0.0 - 1.0 arası)
            
        Returns:
            ThreatSeverity: Tehdit önem derecesi
        """
        if score >= 0.8:
            return ThreatSeverity.CRITICAL
        elif score >= 0.6:
            return ThreatSeverity.HIGH
        elif score >= 0.4:
            return ThreatSeverity.MEDIUM
        elif score >= 0.2:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.UNKNOWN
    
    def _load_signatures(self) -> None:
        """
        İmza veritabanını yükler.
        """
        self.logger.info("İmza veritabanı yükleniyor...")
        
        # Burada gerçek bir imza veritabanı yüklenecek
        # Şimdilik örnek veri ile dolduruyoruz
        
        # Dosya tehditleri için imzalar
        self.signatures["file"] = {
            "known_hashes": {
                "44d88612fea8a8f36de82e1278abb02f": {
                    "name": "Trojan.Win32.Generic",
                    "severity": ThreatSeverity.HIGH
                },
                "5267b02c4e7675adf36d93ae4a4c246b": {
                    "name": "Ransomware.Cryptolocker",
                    "severity": ThreatSeverity.CRITICAL
                }
            },
            "patterns": [
                {
                    "regex": r"\.exe\.(txt|doc|pdf)$",
                    "name": "Suspicious.DoubleExtension",
                    "severity": ThreatSeverity.MEDIUM,
                    "description": "Şüpheli çift uzantılı dosya"
                },
                {
                    "regex": r"(password|credit|bank).*?\.(exe|bat|cmd|ps1)$",
                    "name": "Suspicious.DeceptiveName",
                    "severity": ThreatSeverity.MEDIUM,
                    "description": "Yanıltıcı isimli çalıştırılabilir dosya"
                }
            ]
        }
        
        # Ağ tehditleri için imzalar
        self.signatures["network"] = {
            "ip_blacklist": {
                "185.143.223.12": {
                    "name": "MaliciousHost.C2Server",
                    "severity": ThreatSeverity.HIGH
                },
                "194.5.249.157": {
                    "name": "SpamHost.Generic",
                    "severity": ThreatSeverity.MEDIUM
                }
            },
            "domain_blacklist": {
                "malicious-example.com": {
                    "name": "MaliciousDomain.Phishing",
                    "severity": ThreatSeverity.HIGH
                },
                "evil-tracker.net": {
                    "name": "MaliciousDomain.Tracking",
                    "severity": ThreatSeverity.MEDIUM
                }
            },
            "port_signatures": {
                "4444": {
                    "name": "Suspicious.MetasploitPort",
                    "severity": ThreatSeverity.HIGH
                },
                "1337": {
                    "name": "Suspicious.BackdoorPort",
                    "severity": ThreatSeverity.MEDIUM
                }
            }
        }
        
        # İşlem tehditleri için imzalar
        self.signatures["process"] = {
            "cmd_patterns": [
                {
                    "regex": r"net\s+user\s+administrator",
                    "name": "Suspicious.AdminUserModification",
                    "severity": ThreatSeverity.HIGH,
                    "description": "Yönetici hesabı değişikliği"
                },
                {
                    "regex": r"powershell\s+.*\s+-encod(ed)?cmd",
                    "name": "Suspicious.EncodedPowerShell",
                    "severity": ThreatSeverity.HIGH,
                    "description": "Kodlanmış PowerShell komutu"
                }
            ],
            "process_names": [
                {
                    "regex": r"^(nc|netcat|ncat)\.exe$",
                    "name": "Suspicious.NetworkUtility",
                    "severity": ThreatSeverity.MEDIUM,
                    "description": "Potansiyel olarak kötüye kullanılabilir ağ aracı"
                }
            ]
        }
        
        # IoC desen veritabanını derle
        self._compile_ioc_patterns()
        
        self.logger.info("İmza veritabanı yüklendi")
    
    def _compile_ioc_patterns(self) -> None:
        """
        IoC desenlerini derler.
        """
        # Dosya desenleri
        file_patterns = []
        for pattern in self.signatures["file"]["patterns"]:
            try:
                file_patterns.append({
                    "regex": re.compile(pattern["regex"], re.IGNORECASE),
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern.get("description", "")
                })
            except re.error:
                self.logger.error(f"Geçersiz dosya deseni: {pattern['regex']}")
        
        # İşlem desenleri
        process_cmd_patterns = []
        for pattern in self.signatures["process"]["cmd_patterns"]:
            try:
                process_cmd_patterns.append({
                    "regex": re.compile(pattern["regex"], re.IGNORECASE),
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern.get("description", "")
                })
            except re.error:
                self.logger.error(f"Geçersiz işlem komutu deseni: {pattern['regex']}")
        
        process_name_patterns = []
        for pattern in self.signatures["process"]["process_names"]:
            try:
                process_name_patterns.append({
                    "regex": re.compile(pattern["regex"], re.IGNORECASE),
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern.get("description", "")
                })
            except re.error:
                self.logger.error(f"Geçersiz işlem adı deseni: {pattern['regex']}")
        
        # Derlenmiş desenleri kaydet
        self.ioc_patterns = {
            "file_patterns": file_patterns,
            "process_cmd_patterns": process_cmd_patterns,
            "process_name_patterns": process_name_patterns
        }
    
    def _add_to_memory(self, event: Event) -> None:
        """
        Olayı belleğe ekler.
        
        Args:
            event (Event): Eklenecek olay
        """
        with self.memory_lock:
            event_type = event.type
            
            # Bellek sözlüğünde olay tipi yoksa oluştur
            if event_type not in self.event_memory:
                from collections import deque
                self.event_memory[event_type] = deque(maxlen=100)
            
            # Olayı belleğe ekle
            self.event_memory[event_type].append(event)
    
    def _analyze_file_event(self, event: Event) -> Optional[Threat]:
        """
        Dosya olayını analiz eder.
        
        Args:
            event (Event): Analiz edilecek olay
            
        Returns:
            Optional[Threat]: Tespit edilen tehdit veya None
        """
        # Dosya yolunu al
        file_path = event.details.get("file_path")
        if not file_path:
            return None
        
        # Dosya hash'i varsa kontrol et
        file_hash = event.details.get("file_hash")
        if file_hash:
            known_hash = self.signatures["file"]["known_hashes"].get(file_hash)
            if known_hash:
                # Bilinen zararlı yazılım tespit edildi
                threat = create_threat_from_detection(
                    name=known_hash["name"],
                    category=ThreatCategory.MALWARE,
                    severity=known_hash["severity"],
                    source="threat_analyzer",
                    details={
                        "file_path": file_path,
                        "file_hash": file_hash,
                        "detection_type": "hash_match",
                        "description": "Dosya, bilinen zararlı yazılım imzası ile eşleşiyor.",
                        "recommended_actions": [
                            "Dosyayı karantinaya al",
                            "Dosyayı sil"
                        ]
                    }
                )
                
                # Dosyayı tehdit listesine ekle
                threat.add_affected_file(file_path)
                
                # İstatistikleri güncelle
                self.stats["threats_detected"] += 1
                self.stats["last_detection_time"] = time.time()
                
                self.logger.warning(f"Bilinen zararlı yazılım tespit edildi: {file_path} ({file_hash})")
                return threat
        
        # Dosya adını kontrol et
        file_name = os.path.basename(file_path)
        
        # Şüpheli dosya adı desenleri
        for pattern in self.ioc_patterns["file_patterns"]:
            if pattern["regex"].search(file_name):
                # Şüpheli dosya adı tespit edildi
                threat = create_threat_from_detection(
                    name=pattern["name"],
                    category=ThreatCategory.SUSPICIOUS_PROCESS,
                    severity=pattern["severity"],
                    source="threat_analyzer",
                    details={
                        "file_path": file_path,
                        "file_name": file_name,
                        "detection_type": "name_pattern",
                        "pattern": pattern["regex"].pattern,
                        "description": pattern["description"],
                        "recommended_actions": [
                            "Dosyayı analiz et",
                            "Dosyayı karantinaya al"
                        ]
                    }
                )
                
                # Dosyayı tehdit listesine ekle
                threat.add_affected_file(file_path)
                
                # İstatistikleri güncelle
                self.stats["threats_detected"] += 1
                self.stats["last_detection_time"] = time.time()
                
                self.logger.warning(f"Şüpheli dosya adı tespit edildi: {file_path}")
                return threat
        
        # Tehdit tespit edilmedi
        return None
    
    def _analyze_process_event(self, event: Event) -> Optional[Threat]:
        """
        İşlem olayını analiz eder.
        
        Args:
            event (Event): Analiz edilecek olay
            
        Returns:
            Optional[Threat]: Tespit edilen tehdit veya None
        """
        # İşlem bilgilerini al
        process_path = event.details.get("process_path")
        process_name = event.details.get("process_name") or (
            os.path.basename(process_path) if process_path else None
        )
        process_id = event.details.get("process_id")
        command_line = event.details.get("command_line")
        
        if not process_name or not process_id:
            return None
        
        # İşlem adını kontrol et
        for pattern in self.ioc_patterns["process_name_patterns"]:
            if pattern["regex"].search(process_name):
                # Şüpheli işlem adı tespit edildi
                threat = create_threat_from_detection(
                    name=pattern["name"],
                    category=ThreatCategory.SUSPICIOUS_PROCESS,
                    severity=pattern["severity"],
                    source="threat_analyzer",
                    details={
                        "process_name": process_name,
                        "process_id": process_id,
                        "process_path": process_path,
                        "command_line": command_line,
                        "detection_type": "process_name_pattern",
                        "pattern": pattern["regex"].pattern,
                        "description": pattern["description"],
                        "recommended_actions": [
                            "İşlemi izle",
                            "İşlemi sonlandır"
                        ]
                    }
                )
                
                # İşlemi tehdit listesine ekle
                threat.add_affected_process(process_id)
                
                # Dosya yolu varsa ekle
                if process_path:
                    threat.add_affected_file(process_path)
                
                # İstatistikleri güncelle
                self.stats["threats_detected"] += 1
                self.stats["last_detection_time"] = time.time()
                
                self.logger.warning(f"Şüpheli işlem adı tespit edildi: {process_name} (PID: {process_id})")
                return threat
        
        # Komut satırını kontrol et
        if command_line:
            for pattern in self.ioc_patterns["process_cmd_patterns"]:
                if pattern["regex"].search(command_line):
                    # Şüpheli komut tespit edildi
                    threat = create_threat_from_detection(
                        name=pattern["name"],
                        category=ThreatCategory.SUSPICIOUS_PROCESS,
                        severity=pattern["severity"],
                        source="threat_analyzer",
                        details={
                            "process_name": process_name,
                            "process_id": process_id,
                            "process_path": process_path,
                            "command_line": command_line,
                            "detection_type": "command_line_pattern",
                            "pattern": pattern["regex"].pattern,
                            "description": pattern["description"],
                            "recommended_actions": [
                                "İşlemi sonlandır",
                                "İşlemi analiz et"
                            ]
                        }
                    )
                    
                    # İşlemi tehdit listesine ekle
                    threat.add_affected_process(process_id)
                    
                    # Dosya yolu varsa ekle
                    if process_path:
                        threat.add_affected_file(process_path)
                    
                    # İstatistikleri güncelle
                    self.stats["threats_detected"] += 1
                    self.stats["last_detection_time"] = time.time()
                    
                    self.logger.warning(f"Şüpheli komut tespit edildi: {process_name} (PID: {process_id})")
                    return threat
        
        # Tehdit tespit edilmedi
        return None
    
    def _analyze_network_event(self, event: Event) -> Optional[Threat]:
        """
        Ağ olayını analiz eder.
        
        Args:
            event (Event): Analiz edilecek olay
            
        Returns:
            Optional[Threat]: Tespit edilen tehdit veya None
        """
        # Bağlantı tipi kontrolü
        connection_type = event.details.get("connection_type")
        if connection_type == "dns_query":
            # DNS sorgusu olayı
            return self._analyze_dns_query(event.details.get("dns_info", {}))
        
        # Normal bağlantı olayı
        connection_id = event.details.get("connection_id")
        connection_info = event.details.get("connection_info", {})
        
        if not connection_info:
            return None
        
        # IP adresini kontrol et
        remote_ip = connection_info.get("remote_address")
        if remote_ip:
            blacklisted_ip = self.signatures["network"]["ip_blacklist"].get(remote_ip)
            if blacklisted_ip:
                # Bilinen kötü amaçlı IP tespit edildi
                threat = create_threat_from_detection(
                    name=blacklisted_ip["name"],
                    category=ThreatCategory.NETWORK,
                    severity=blacklisted_ip["severity"],
                    source="threat_analyzer",
                    details={
                        "connection_id": connection_id,
                        "remote_ip": remote_ip,
                        "remote_port": connection_info.get("remote_port"),
                        "local_port": connection_info.get("local_port"),
                        "protocol": connection_info.get("protocol"),
                        "process_name": connection_info.get("process_name"),
                        "detection_type": "blacklisted_ip",
                        "description": "Bilinen kötü amaçlı IP adresi ile bağlantı",
                        "recommended_actions": [
                            "Bağlantıyı kapat",
                            "IP'yi engelle"
                        ]
                    }
                )
                
                # İşlem ID varsa ekle
                process_id = connection_info.get("process_id")
                if process_id:
                    threat.add_affected_process(process_id)
                
                # İstatistikleri güncelle
                self.stats["threats_detected"] += 1
                self.stats["last_detection_time"] = time.time()
                
                self.logger.warning(f"Bilinen kötü amaçlı IP tespit edildi: {remote_ip}")
                return threat
        
        # Port kontrolü
        remote_port = connection_info.get("remote_port")
        if remote_port:
            port_str = str(remote_port)
            suspicious_port = self.signatures["network"]["port_signatures"].get(port_str)
            if suspicious_port:
                # Şüpheli port tespit edildi
                threat = create_threat_from_detection(
                    name=suspicious_port["name"],
                    category=ThreatCategory.SUSPICIOUS_CONNECTION,
                    severity=suspicious_port["severity"],
                    source="threat_analyzer",
                    details={
                        "connection_id": connection_id,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "local_port": connection_info.get("local_port"),
                        "protocol": connection_info.get("protocol"),
                        "process_name": connection_info.get("process_name"),
                        "detection_type": "suspicious_port",
                        "description": f"Şüpheli porta bağlantı ({port_str})",
                        "recommended_actions": [
                            "Bağlantıyı izle",
                            "Bağlantıyı kapat"
                        ]
                    }
                )
                
                # İşlem ID varsa ekle
                process_id = connection_info.get("process_id")
                if process_id:
                    threat.add_affected_process(process_id)
                
                # İstatistikleri güncelle
                self.stats["threats_detected"] += 1
                self.stats["last_detection_time"] = time.time()
                
                self.logger.warning(f"Şüpheli port bağlantısı tespit edildi: {remote_ip}:{remote_port}")
                return threat
        
        # Tehdit tespit edilmedi
        return None
    
    def _analyze_dns_query(self, dns_info: Dict[str, Any]) -> Optional[Threat]:
        """
        DNS sorgusu olayını analiz eder.
        
        Args:
            dns_info (Dict[str, Any]): DNS sorgusu bilgileri
            
        Returns:
            Optional[Threat]: Tespit edilen tehdit veya None
        """
        # DNS sorgu bilgilerini kontrol et
        query_domain = dns_info.get("query_domain")
        
        if not query_domain:
            return None
        
        # Alan adını normalleştir
        query_domain = query_domain.lower()
        
        # Kara listedeki alan adını kontrol et
        blacklisted_domain = self.signatures["network"]["domain_blacklist"].get(query_domain)
        if blacklisted_domain:
            # Bilinen kötü amaçlı alan adı tespit edildi
            threat = create_threat_from_detection(
                name=blacklisted_domain["name"],
                category=ThreatCategory.NETWORK,
                severity=blacklisted_domain["severity"],
                source="threat_analyzer",
                details={
                    "domain": query_domain,
                    "query_type": dns_info.get("query_type"),
                    "response_ip": dns_info.get("response_ip"),
                    "process_name": dns_info.get("process_name"),
                    "detection_type": "blacklisted_domain",
                    "description": "Bilinen kötü amaçlı alan adına DNS sorgusu",
                    "recommended_actions": [
                        "Alan adını engelle",
                        "İşlemi izole et"
                    ]
                }
            )
            
            # İşlem ID varsa ekle
            process_id = dns_info.get("process_id")
            if process_id:
                threat.add_affected_process(process_id)
            
            # İstatistikleri güncelle
            self.stats["threats_detected"] += 1
            self.stats["last_detection_time"] = time.time()
            
            self.logger.warning(f"Bilinen kötü amaçlı alan adı tespit edildi: {query_domain}")
            return threat
        
        # Şüpheli alan adı kontrolü
        # Örnek: Algoritmik şüpheli alan adı tespiti
        is_suspicious, score, reason = self._is_suspicious_domain(query_domain)
        if is_suspicious:
            # Şüpheli alan adı tespit edildi
            severity = self.classify_severity(score)
            
            threat = create_threat_from_detection(
                name="Suspicious.DomainName",
                category=ThreatCategory.NETWORK,
                severity=severity,
                source="threat_analyzer",
                details={
                    "domain": query_domain,
                    "query_type": dns_info.get("query_type"),
                    "response_ip": dns_info.get("response_ip"),
                    "process_name": dns_info.get("process_name"),
                    "detection_type": "suspicious_domain",
                    "score": score,
                    "reason": reason,
                    "description": f"Şüpheli alan adı tespit edildi: {reason}",
                    "recommended_actions": [
                        "Alan adını izle",
                        "İşlemi kontrol et"
                    ]
                }
            )
            
            # İşlem ID varsa ekle
            process_id = dns_info.get("process_id")
            if process_id:
                threat.add_affected_process(process_id)
            
            # İstatistikleri güncelle
            self.stats["threats_detected"] += 1
            self.stats["last_detection_time"] = time.time()
            
            self.logger.warning(f"Şüpheli alan adı tespit edildi: {query_domain} ({reason})")
            return threat
        
        # Tehdit tespit edilmedi
        return None
    
    def _analyze_network_alert(self, event: Event) -> Optional[Threat]:
        """
        Ağ uyarısı olayını analiz eder.
        
        Args:
            event (Event): Analiz edilecek olay
            
        Returns:
            Optional[Threat]: Tespit edilen tehdit veya None
        """
        # Uyarı bilgilerini al
        alert_type = event.details.get("alert_type")
        
        if not alert_type:
            return None
        
        # Uyarı tipine göre işle
        if alert_type == "port_scan":
            # Port tarama uyarısı
            scan_info = event.details.get("scan_info", {})
            
            if not scan_info:
                return None
            
            # Port tarama tehdidi oluştur
            threat = create_threat_from_detection(
                name="Intrusion.PortScan",
                category=ThreatCategory.INTRUSION,
                severity=ThreatSeverity.MEDIUM,
                source="threat_analyzer",
                details={
                    "source_ip": scan_info.get("source_ip"),
                    "target_ip": scan_info.get("target_ip"),
                    "ports_scanned": scan_info.get("ports_scanned", []),
                    "scan_duration": scan_info.get("scan_duration"),
                    "scan_type": scan_info.get("scan_type"),
                    "detection_type": "port_scan",
                    "description": "Port tarama girişimi tespit edildi",
                    "recommended_actions": [
                        "Kaynak IP'yi geçici olarak engelle",
                        "Güvenlik duvarı kurallarını güçlendir"
                    ]
                }
            )
            
            # İstatistikleri güncelle
            self.stats["threats_detected"] += 1
            self.stats["last_detection_time"] = time.time()
            
            self.logger.warning(f"Port tarama tehdidi tespit edildi: {scan_info.get('source_ip')} -> {scan_info.get('target_ip')}")
            return threat
            
        elif alert_type == "suspicious_connection":
            # Şüpheli bağlantı uyarısı
            connection_id = event.details.get("connection_id")
            connection_info = event.details.get("connection_info", {})
            reason = event.details.get("reason", "Bilinmeyen şüpheli bağlantı")
            
            if not connection_info:
                return None
            
            # Şüpheli bağlantı tehdidi oluştur
            threat = create_threat_from_detection(
                name="Network.SuspiciousConnection",
                category=ThreatCategory.SUSPICIOUS_CONNECTION,
                severity=ThreatSeverity.MEDIUM,
                source="threat_analyzer",
                details={
                    "connection_id": connection_id,
                    "remote_address": connection_info.get("remote_address"),
                    "remote_port": connection_info.get("remote_port"),
                    "protocol": connection_info.get("protocol"),
                    "process_name": connection_info.get("process_name"),
                    "detection_type": "suspicious_connection",
                    "reason": reason,
                    "description": f"Şüpheli ağ bağlantısı: {reason}",
                    "recommended_actions": [
                        "Bağlantıyı kapat",
                        "İşlemi izole et"
                    ]
                }
            )
            
            # İşlem ID varsa ekle
            process_id = connection_info.get("process_id")
            if process_id:
                threat.add_affected_process(process_id)
            
            # İstatistikleri güncelle
            self.stats["threats_detected"] += 1
            self.stats["last_detection_time"] = time.time()
            
            self.logger.warning(f"Şüpheli bağlantı tehdidi tespit edildi: {connection_info.get('remote_address')}:{connection_info.get('remote_port')}")
            return threat
            
        elif alert_type == "suspicious_dns":
            # Şüpheli DNS sorgusu uyarısı
            dns_info = event.details.get("dns_info", {})
            domain = event.details.get("domain") or dns_info.get("query_domain")
            reason = event.details.get("reason", "Bilinmeyen şüpheli DNS sorgusu")
            
            if not domain:
                return None
            
            # Şüpheli DNS sorgusu tehdidi oluştur
            threat = create_threat_from_detection(
                name="Network.SuspiciousDNS",
                category=ThreatCategory.NETWORK,
                severity=ThreatSeverity.MEDIUM,
                source="threat_analyzer",
                details={
                    "domain": domain,
                    "response_ip": dns_info.get("response_ip"),
                    "process_name": dns_info.get("process_name"),
                    "detection_type": "suspicious_dns",
                    "reason": reason,
                    "description": f"Şüpheli DNS sorgusu: {reason}",
                    "recommended_actions": [
                        "Alan adını engelle",
                        "İşlemi izole et"
                    ]
                }
            )
            
            # İşlem ID varsa ekle
            process_id = dns_info.get("process_id")
            if process_id:
                threat.add_affected_process(process_id)
            
            # İstatistikleri güncelle
            self.stats["threats_detected"] += 1
            self.stats["last_detection_time"] = time.time()
            
            self.logger.warning(f"Şüpheli DNS sorgusu tehdidi tespit edildi: {domain}")
            return threat
        
        # Tehdit tespit edilmedi
        return None
    
    def _analyze_system_change(self, event: Event) -> Optional[Threat]:
        """
        Sistem değişikliği olayını analiz eder.
        
        Args:
            event (Event): Analiz edilecek olay
            
        Returns:
            Optional[Threat]: Tespit edilen tehdit veya None
        """
        # Değişiklik bilgilerini al
        change_type = event.details.get("change_type")
        change_details = event.details.get("details", {})
        
        if not change_type or not change_details:
            return None
        
        # Değişiklik tipine göre işle
        if change_type == "registry":
            # Kayıt defteri değişikliği
            registry_key = change_details.get("key")
            registry_value = change_details.get("value")
            old_data = change_details.get("old_data")
            new_data = change_details.get("new_data")
            
            if not registry_key:
                return None
            
            # Kritik sistem ayarları kontrolü
            critical_keys = [
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
                r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            ]
            
            is_critical = any(registry_key.startswith(key) for key in critical_keys)
            
            if is_critical:
                # Kritik kayıt defteri değişikliği tehdidi oluştur
                threat = create_threat_from_detection(
                    name="System.CriticalRegistryChange",
                    category=ThreatCategory.SYSTEM,
                    severity=ThreatSeverity.HIGH,
                    source="threat_analyzer",
                    details={
                        "registry_key": registry_key,
                        "registry_value": registry_value,
                        "old_data": old_data,
                        "new_data": new_data,
                        "process_name": change_details.get("process_name"),
                        "detection_type": "critical_registry_change",
                        "description": "Kritik sistem ayarları değiştirildi",
                        "recommended_actions": [
                            "Değişikliği geri al",
                            "İşlemi izole et"
                        ]
                    }
                )
                
                # İşlem ID varsa ekle
                process_id = change_details.get("process_id")
                if process_id:
                    threat.add_affected_process(process_id)
                
                # İstatistikleri güncelle
                self.stats["threats_detected"] += 1
                self.stats["last_detection_time"] = time.time()
                
                self.logger.warning(f"Kritik kayıt defteri değişikliği tehdidi tespit edildi: {registry_key}")
                return threat
        
        elif change_type == "hosts_file":
            # Hosts dosyası değişikliği
            added_entries = change_details.get("added_entries", [])
            
            if not added_entries:
                return None
            
            # Önemli alan adları kontrolü
            important_domains = [
                "google.com", "microsoft.com", "windows.com", "windowsupdate.com",
                "facebook.com", "twitter.com", "apple.com", "icloud.com",
                "yahoo.com", "amazon.com", "github.com", "live.com"
            ]
            
            suspicious_entries = []
            for entry in added_entries:
                domain = entry.get("domain")
                if domain and any(domain.endswith(d) for d in important_domains):
                    suspicious_entries.append(entry)
            
            if suspicious_entries:
                # Şüpheli hosts dosyası değişikliği tehdidi oluştur
                threat = create_threat_from_detection(
                    name="System.HostsFileModification",
                    category=ThreatCategory.SYSTEM,
                    severity=ThreatSeverity.HIGH,
                    source="threat_analyzer",
                    details={
                        "suspicious_entries": suspicious_entries,
                        "process_name": change_details.get("process_name"),
                        "detection_type": "hosts_file_modification",
                        "description": "Önemli alan adları hosts dosyasında değiştirildi",
                        "recommended_actions": [
                            "Değişiklikleri geri al",
                            "İşlemi izole et"
                        ]
                    }
                )
                
                # İşlem ID varsa ekle
                process_id = change_details.get("process_id")
                if process_id:
                    threat.add_affected_process(process_id)
                
                # İstatistikleri güncelle
                self.stats["threats_detected"] += 1
                self.stats["last_detection_time"] = time.time()
                
                self.logger.warning(f"Hosts dosyası değişikliği tehdidi tespit edildi: {len(suspicious_entries)} şüpheli girdi")
                return threat
        
        # Tehdit tespit edilmedi
        return None
    
    def _evaluate_ip_ioc(self, ip: str) -> Tuple[bool, float, str]:
        """
        IP adresini IoC olarak değerlendirir.
        
        Args:
            ip (str): Değerlendirilecek IP adresi
            
        Returns:
            Tuple[bool, float, str]: (Tehdit mi?, Tehdit skoru, Açıklama)
        """
        # Kara listedeki IP'yi kontrol et
        if ip in self.signatures["network"]["ip_blacklist"]:
            return True, 1.0, "Bilinen kötü amaçlı IP adresi"
        
        # Beyaz listedeki IP'yi kontrol et
        if ip in self.whitelisted_ips:
            return False, 0.0, "Güvenli listedeki IP adresi"
        
        # Algoritmik kontrol yapılabilir
        # Şimdilik basit olarak tehdit skoru 0
        return False, 0.0, "Tehdit tespit edilmedi"
    
    def _evaluate_domain_ioc(self, domain: str) -> Tuple[bool, float, str]:
        """
        Alan adını IoC olarak değerlendirir.
        
        Args:
            domain (str): Değerlendirilecek alan adı
            
        Returns:
            Tuple[bool, float, str]: (Tehdit mi?, Tehdit skoru, Açıklama)
        """
        # Alan adını normalleştir
        domain = domain.lower()
        
        # Kara listedeki alan adını kontrol et
        if domain in self.signatures["network"]["domain_blacklist"]:
            return True, 1.0, "Bilinen kötü amaçlı alan adı"
        
        # Beyaz listedeki alan adını kontrol et
        if self._is_whitelisted_domain(domain):
            return False, 0.0, "Güvenli listedeki alan adı"
        
        # Şüpheli alan adı kontrolü
        is_suspicious, score, reason = self._is_suspicious_domain(domain)
        if is_suspicious:
            return True, score, reason
        
        return False, 0.0, "Tehdit tespit edilmedi"
    
    def _evaluate_hash_ioc(self, file_hash: str) -> Tuple[bool, float, str]:
        """
        Dosya hash'ini IoC olarak değerlendirir.
        
        Args:
            file_hash (str): Değerlendirilecek dosya hash'i
            
        Returns:
            Tuple[bool, float, str]: (Tehdit mi?, Tehdit skoru, Açıklama)
        """
        # Bilinen zararlı hash'i kontrol et
        if file_hash in self.signatures["file"]["known_hashes"]:
            malware_info = self.signatures["file"]["known_hashes"][file_hash]
            return True, 1.0, f"Bilinen zararlı yazılım: {malware_info['name']}"
        
        return False, 0.0, "Tehdit tespit edilmedi"
    
    def _evaluate_url_ioc(self, url: str) -> Tuple[bool, float, str]:
        """
        URL'yi IoC olarak değerlendirir.
        
        Args:
            url (str): Değerlendirilecek URL
            
        Returns:
            Tuple[bool, float, str]: (Tehdit mi?, Tehdit skoru, Açıklama)
        """
        # URL'den alan adını çıkar
        import re
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            # Alan adını değerlendir
            return self._evaluate_domain_ioc(domain)
        
        return False, 0.0, "Tehdit tespit edilmedi"
    
    def _is_whitelisted_domain(self, domain: str) -> bool:
        """
        Alan adının güvenli listede olup olmadığını kontrol eder.
        
        Args:
            domain (str): Kontrol edilecek alan adı
            
        Returns:
            bool: Alan adı güvenli listede mi?
        """
        # Tam eşleşme kontrolü
        if domain in self.whitelisted_domains:
            return True
        
        # Alt alan adı kontrolü
        domain_parts = domain.split('.')
        
        for i in range(1, len(domain_parts)):
            parent_domain = '.'.join(domain_parts[i:])
            if parent_domain in self.whitelisted_domains:
                return True
        
        return False
    
    def _is_suspicious_domain(self, domain: str) -> Tuple[bool, float, str]:
        """
        Alan adının şüpheli olup olmadığını kontrol eder.
        
        Args:
            domain (str): Kontrol edilecek alan adı
            
        Returns:
            Tuple[bool, float, str]: (Şüpheli mi?, Şüphe skoru, Açıklama)
        """
        # Şüpheli alan adı kontrolleri
        domain = domain.lower()
        
        # Şüpheli kelimeler
        suspicious_keywords = [
            'secure', 'account', 'update', 'banking', 'login', 'verify',
            'paypal', 'ebay', 'amazon', 'microsoft', 'apple', 'google',
            'facebook', 'twitter', 'instagram', 'signin', 'security'
        ]
        
        # Alan adında şüpheli kelime varsa
        for keyword in suspicious_keywords:
            if keyword in domain:
                # Alan adının kendisi mi, yoksa bir alt alan adı mı?
                domain_parts = domain.split('.')
                base_domain = '.'.join(domain_parts[-2:])
                
                # Bilinen bir hizmetin adını içeren alt alan adı
                if keyword in ['paypal', 'ebay', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'twitter', 'instagram']:
                    if keyword in domain and keyword not in base_domain:
                        return True, 0.8, f"Bilinen hizmet adını içeren şüpheli alt alan adı: {keyword}"
        
        # Algoritmik entropi kontrolü
        if self._domain_has_high_entropy(domain):
            return True, 0.6, "Yüksek entropi değerine sahip alan adı"
        
        # Çok uzun alan adı
        if len(domain) > 40:
            return True, 0.4, "Aşırı uzun alan adı"
        
        # Çok fazla sayı içeren alan adı
        digits_count = sum(c.isdigit() for c in domain)
        if digits_count > len(domain) / 3:
            return True, 0.5, "Çok fazla rakam içeren alan adı"
        
        # Şüpheli TLD kontrolü
        tld = domain.split('.')[-1].lower()
        suspicious_tlds = ['xyz', 'top', 'gq', 'tk', 'ml', 'ga', 'cf']
        if tld in suspicious_tlds:
            return True, 0.4, f"Şüpheli üst düzey alan adı (TLD): .{tld}"
        
        # Şüpheli kalıp kontrolü
        if re.search(r'[a-z0-9]{16,}\.', domain):
            return True, 0.7, "Rastgele karakter dizisine benzeyen alt alan adı"
        
        # Şüpheli değil
        return False, 0.0, "Şüpheli değil"
    
    def _domain_has_high_entropy(self, domain: str) -> bool:
        """
        Alan adının yüksek entropi (rastgelelik) içerip içermediğini kontrol eder.
        
        Args:
            domain (str): Kontrol edilecek alan adı
            
        Returns:
            bool: Alan adı yüksek entropi içeriyor mu?
        """
        import math
        
        # TLD kısmını çıkar
        parts = domain.split('.')
        if len(parts) > 1:
            domain_name = '.'.join(parts[:-1])
        else:
            domain_name = domain
        
        # Çok kısa alan adlarını atla
        if len(domain_name) < 10:
            return False
        
        # Shannon entropi hesaplama
        char_counts = {}
        for char in domain_name:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        for count in char_counts.values():
            freq = count / len(domain_name)
            entropy -= freq * math.log2(freq)
        
        # 3.5 ve üzeri entropi değeri şüpheli kabul edilir
        # (Rastgele oluşturulmuş diziler genellikle 3.5+ entropi değerine sahiptir)
        return entropy > 3.5