#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GuardCore Çekirdek İşlem Motoru
--------------------------------
Bu modül, GuardCore sisteminin ana motor bileşenini içerir.
Tüm koruma, izleme ve düzeltme modüllerini yönetir ve koordine eder.

Yazarlar: GuardCore Dev Team
Lisans: MIT
Versiyon: 0.1.0
"""

import os
import time
import logging
import threading
import importlib
from typing import Dict, List, Any, Optional, Type

from guardcore.core.scheduler import Scheduler
from guardcore.core.resource_manager import ResourceManager
from guardcore.core.threat_analyzer import ThreatAnalyzer
from guardcore.modules.common.event import Event, EventType, EventSeverity
from guardcore.modules.common.threat import Threat, ThreatStatus
from guardcore.db.repository import Repository


class CoreEngine:
    """
    GuardCore Çekirdek İşlem Motoru
    
    Bu sınıf, tüm koruma sistemi modüllerini koordine eden ana motordur.
    Modüllerin yüklenmesi, olayların işlenmesi ve sistem durumunun yönetiminden sorumludur.
    """
    
    def __init__(self, settings):
        """
        CoreEngine'i başlatır.
        
        Args:
            settings (Settings): Yapılandırma ayarları
        """
        self.logger = logging.getLogger(__name__)
        self.settings = settings
        self.is_running = False
        
        # Alt bileşenleri başlat
        self.scheduler = Scheduler()
        self.resource_manager = ResourceManager(settings)
        self.threat_analyzer = ThreatAnalyzer(settings)
        self.repository = Repository(settings)
        
        # Modülleri tutacak sözlükler
        self.protection_modules = {}
        self.monitoring_modules = {}
        self.remediation_modules = {}
        
        # Olay ve tehdit kuyruğu
        self.event_queue = []
        self.event_queue_lock = threading.Lock()
        
        # İşlem iş parçacıkları
        self.threads = {
            'event_processor': None,
            'module_supervisor': None
        }
        
        self.logger.info("CoreEngine hazırlandı")
    
    def start(self):
        """Tüm motor bileşenlerini ve modüllerini başlatır"""
        if self.is_running:
            self.logger.warning("CoreEngine zaten çalışıyor")
            return
        
        self.logger.info("CoreEngine başlatılıyor...")
        self.is_running = True
        
        try:
            # Veritabanını başlat
            self.repository.connect()
            
            # Alt bileşenleri başlat
            self.scheduler.start()
            self.resource_manager.start()
            self.threat_analyzer.start()
            
            # Modülleri yükle
            self._load_modules()
            
            # İşlem iş parçacıklarını başlat
            self.threads['event_processor'] = threading.Thread(
                target=self._event_processor_loop,
                daemon=True,
                name="EventProcessor"
            )
            self.threads['event_processor'].start()
            
            self.threads['module_supervisor'] = threading.Thread(
                target=self._module_supervisor_loop,
                daemon=True,
                name="ModuleSupervisor"
            )
            self.threads['module_supervisor'].start()
            
            # Başlangıç sistem taramasını zamanla
            if self.settings.get("system.startup_scan", True):
                self.scheduler.schedule_task(
                    self._run_startup_scan,
                    delay=60,  # 1 dakika sonra
                    name="StartupScan"
                )
            
            self.logger.info("CoreEngine başarıyla başlatıldı")
        
        except Exception as e:
            self.is_running = False
            self.logger.error(f"CoreEngine başlatma hatası: {e}", exc_info=True)
            raise
    
    def stop(self):
        """Tüm motor bileşenlerini ve modüllerini durdurur"""
        if not self.is_running:
            return
        
        self.logger.info("CoreEngine durduruluyor...")
        self.is_running = False
        
        # Tüm modülleri durdur
        self._stop_all_modules()
        
        # Alt bileşenleri durdur
        self.threat_analyzer.stop()
        self.resource_manager.stop()
        self.scheduler.stop()
        
        # Veritabanı bağlantısını kapat
        self.repository.disconnect()
        
        # İş parçacıklarının durmasını bekle
        for thread_name, thread in self.threads.items():
            if thread and thread.is_alive():
                self.logger.debug(f"{thread_name} iş parçacığı bekleniyor...")
                thread.join(timeout=3.0)
        
        self.logger.info("CoreEngine durduruldu")
    
    def process_event(self, event: Event):
        """
        Bir güvenlik olayını işleme kuyruğuna ekler
        
        Args:
            event (Event): İşlenecek güvenlik olayı
        """
        with self.event_queue_lock:
            self.event_queue.append(event)
            self.logger.debug(f"Olay kuyruğa eklendi: {event.id} ({event.type.name})")
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Mevcut sistem güvenlik durumunu döndürür
        
        Returns:
            Dict[str, Any]: Sistem durumu bilgilerini içeren sözlük
        """
        # Örnek bir durum raporu hazırla
        status = {
            "timestamp": time.time(),
            "protection_status": self._get_protection_status(),
            "threat_count": self.repository.get_active_threat_count(),
            "last_scan": self.repository.get_last_scan_info(),
            "resource_usage": self.resource_manager.get_usage_stats(),
            "module_status": self._get_all_module_status()
        }
        
        return status
    
    def run_scan(self, scan_type: str = "quick") -> str:
        """
        Sistem taraması başlatır
        
        Args:
            scan_type (str): Tarama tipi. "quick", "full" veya "custom"
            
        Returns:
            str: Tarama ID'si
        """
        self.logger.info(f"{scan_type.capitalize()} tarama başlatılıyor...")
        
        # Tarama ID'si oluştur
        scan_id = f"scan_{int(time.time())}"
        
        # Taramayı yapılandır
        scan_config = {
            "id": scan_id,
            "type": scan_type,
            "start_time": time.time()
        }
        
        # Taramayı zamanla (tarama tipine göre öncelik ayarla)
        if scan_type == "quick":
            # Hızlı tarama hemen başlar
            self.scheduler.schedule_task(
                self._execute_scan,
                args=(scan_config,),
                delay=0,
                priority=10,
                name=f"Scan_{scan_id}"
            )
        else:
            # Tam taramalar daha düşük öncelikle zamanlanır
            self.scheduler.schedule_task(
                self._execute_scan,
                args=(scan_config,),
                delay=2,
                priority=5,
                name=f"Scan_{scan_id}"
            )
        
        return scan_id
    
    def _load_modules(self):
        """Tüm güvenlik modüllerini yapılandırmaya göre yükler"""
        self.logger.info("Modüller yükleniyor...")
        
        # Koruma modüllerini yükle
        self._load_module_group("protection", self.protection_modules)
        
        # İzleme modüllerini yükle
        self._load_module_group("monitoring", self.monitoring_modules)
        
        # Düzeltme modüllerini yükle
        self._load_module_group("remediation", self.remediation_modules)
        
        self.logger.info(f"Toplam {len(self.protection_modules) + len(self.monitoring_modules) + len(self.remediation_modules)} modül yüklendi")
    
    def _load_module_group(self, group_name: str, module_dict: Dict):
        """
        Belirli bir grup modülü yükler
        
        Args:
            group_name (str): Modül grubu adı
            module_dict (Dict): Modüllerin saklanacağı sözlük
        """
        self.logger.debug(f"{group_name.capitalize()} modülleri yükleniyor...")
        
        # Yapılandırmadan etkin modülleri al
        enabled_modules = self.settings.get(f"modules.{group_name}.enabled", [])
        
        for module_name in enabled_modules:
            try:
                # Tam modül yolu
                module_path = f"guardcore.modules.{group_name}.{module_name}"
                
                # Modülü dinamik olarak içe aktar
                module = importlib.import_module(module_path)
                
                # Ana sınıfı bul (modül adını büyük harfle başlat ve "Module" ekle)
                class_name = module_name.title().replace('_', '') + "Module"
                module_class = getattr(module, class_name)
                
                # Modül örneğini oluştur
                module_instance = module_class(
                    engine=self,
                    settings=self.settings
                )
                
                # Modülü başlat
                module_instance.initialize()
                
                # Modülü sözlüğe ekle
                module_dict[module_name] = module_instance
                
                self.logger.debug(f"{module_name} modülü yüklendi")
                
            except Exception as e:
                self.logger.error(f"{module_name} modülü yüklenirken hata: {e}", exc_info=True)
    
    def _stop_all_modules(self):
        """Tüm modülleri durdurur"""
        self.logger.debug("Tüm modüller durduruluyor...")
        
        # Tüm modül gruplarını birleştir
        all_modules = {
            **self.protection_modules,
            **self.monitoring_modules,
            **self.remediation_modules
        }
        
        # Her bir modülü durdur
        for name, module in all_modules.items():
            try:
                module.shutdown()
                self.logger.debug(f"{name} modülü durduruldu")
            except Exception as e:
                self.logger.error(f"{name} modülü durdurulurken hata: {e}")
    
    def _event_processor_loop(self):
        """Olay işleme döngüsü"""
        self.logger.debug("Olay işleyici iş parçacığı başlatıldı")
        
        while self.is_running:
            # Kuyrukta olay var mı kontrol et
            events_to_process = []
            
            with self.event_queue_lock:
                if self.event_queue:
                    # En fazla 10 olayı işleme için al
                    events_to_process = self.event_queue[:10]
                    self.event_queue = self.event_queue[10:]
            
            # Olayları işle
            for event in events_to_process:
                try:
                    self._process_single_event(event)
                except Exception as e:
                    self.logger.error(f"Olay işlenirken hata: {e}", exc_info=True)
            
            # Kuyrukta olay yoksa biraz bekle
            if not events_to_process:
                time.sleep(0.1)
    
    def _process_single_event(self, event: Event):
        """
        Tek bir olayı işler
        
        Args:
            event (Event): İşlenecek olay
        """
        self.logger.debug(f"Olay işleniyor: {event.id} ({event.type.name})")
        
        # Olayı veritabanına kaydet
        self.repository.save_event(event)
        
        # Tehdit analizi yap
        if event.needs_analysis:
            threat = self.threat_analyzer.analyze_event(event)
            
            # Eğer bir tehdit tespit edildiyse
            if threat:
                self.logger.warning(f"Tehdit tespit edildi: {threat.id} ({threat.severity.name})")
                self._handle_threat(threat)
        
        # Olay tipine göre özel işlem yap
        if event.type == EventType.SCAN_COMPLETE:
            self._handle_scan_complete(event)
        elif event.type == EventType.SYSTEM_CHANGE:
            self._handle_system_change(event)
        elif event.type == EventType.NETWORK_ALERT:
            self._handle_network_alert(event)
    
    def _handle_threat(self, threat: Threat):
        """
        Tespit edilen bir tehdidi işler
        
        Args:
            threat (Threat): İşlenecek tehdit
        """
        # Tehdidi veritabanına kaydet
        self.repository.save_threat(threat)
        
        # Otomatik yanıt gerekiyor mu?
        if threat.severity >= ThreatStatus.HIGH:
            # Acil yanıt gerekiyor
            self._execute_immediate_response(threat)
        else:
            # Zamanlanmış yanıt yeterli
            self._schedule_threat_response(threat)
        
        # UI bildirimini gönder
        self._send_threat_notification(threat)
    
    def _execute_immediate_response(self, threat: Threat):
        """
        Kritik bir tehdide acil yanıt verir
        
        Args:
            threat (Threat): İşlenecek tehdit
        """
        self.logger.warning(f"Tehdit için acil yanıt uygulanıyor: {threat.id}")
        
        # İlgili düzeltme modülünü bul ve uygula
        if "malware" in threat.category:
            if "antimalware" in self.protection_modules:
                module = self.protection_modules["antimalware"]
                module.respond_to_threat(threat)
        elif "network" in threat.category:
            if "firewall" in self.protection_modules:
                module = self.protection_modules["firewall"]
                module.respond_to_threat(threat)
        
        # Tehdit karantinaya alındıysa durumunu güncelle
        if threat.status == ThreatStatus.QUARANTINED:
            self.repository.update_threat_status(threat.id, ThreatStatus.QUARANTINED)
    
    def _schedule_threat_response(self, threat: Threat):
        """
        Daha düşük öncelikli bir tehdit için yanıt zamanlar
        
        Args:
            threat (Threat): İşlenecek tehdit
        """
        self.logger.info(f"Tehdit yanıtı zamanlanıyor: {threat.id}")
        
        # İşlemi zamanlayıcıya ekle
        self.scheduler.schedule_task(
            self._execute_threat_response,
            args=(threat.id,),
            delay=30,  # 30 saniye sonra
            priority=5,
            name=f"ThreatResponse_{threat.id}"
        )
    
    def _execute_threat_response(self, threat_id: str):
        """
        Zamanlanmış tehdit yanıtını uygular
        
        Args:
            threat_id (str): Tehdit ID'si
        """
        # Tehdit bilgisini al
        threat = self.repository.get_threat(threat_id)
        
        if not threat:
            self.logger.error(f"Tehdit bulunamadı: {threat_id}")
            return
        
        self.logger.info(f"Zamanlanmış tehdit yanıtı uygulanıyor: {threat_id}")
        
        # İlgili düzeltme modülünü bul ve uygula
        for module_name, module in self.remediation_modules.items():
            if module.can_handle_threat(threat):
                success = module.handle_threat(threat)
                if success:
                    self.logger.info(f"Tehdit başarıyla ele alındı: {threat_id}")
                    break
    
    def _send_threat_notification(self, threat: Threat):
        """
        Kullanıcıya tehdit bildirimi gönderir
        
        Args:
            threat (Threat): Bildirimi gönderilecek tehdit
        """
        # Bu kısım UI API ile entegre edilecek
        # Şimdilik sadece log kaydı
        self.logger.info(f"UI için tehdit bildirimi oluşturuldu: {threat.id}")
    
    def _module_supervisor_loop(self):
        """Modül sağlık durumunu izleyen döngü"""
        self.logger.debug("Modül denetleyici iş parçacığı başlatıldı")
        
        while self.is_running:
            try:
                self._check_module_health()
            except Exception as e:
                self.logger.error(f"Modül sağlık kontrolü sırasında hata: {e}")
            
            # Her 60 saniyede bir kontrol et
            time.sleep(60)
    
    def _check_module_health(self):
        """Tüm modüllerin sağlık durumunu kontrol eder"""
        all_modules = {
            **self.protection_modules,
            **self.monitoring_modules,
            **self.remediation_modules
        }
        
        for name, module in all_modules.items():
            try:
                # Modül yanıt veriyor mu kontrol et
                if not module.is_healthy():
                    self.logger.warning(f"{name} modülü sağlıklı görünmüyor, yeniden başlatılıyor")
                    module.restart()
            except Exception as e:
                self.logger.error(f"{name} modülü kontrol edilirken hata: {e}")
    
    def _run_startup_scan(self):
        """Başlangıç sistem taramasını çalıştırır"""
        self.logger.info("Başlangıç sistem taraması başlatılıyor")
        self.run_scan("quick")
    
    def _execute_scan(self, scan_config: Dict[str, Any]):
        """
        Sistem taramasını yürütür
        
        Args:
            scan_config (Dict[str, Any]): Tarama yapılandırması
        """
        scan_id = scan_config["id"]
        scan_type = scan_config["type"]
        
        self.logger.info(f"{scan_type.capitalize()} tarama başlatıldı: {scan_id}")
        
        # Tarama başlangıç kaydını oluştur
        self.repository.create_scan_record(scan_id, scan_type)
        
        try:
            # Tarama işlemini modüllere devret
            if scan_type == "quick":
                # Hızlı tarama için ilgili modülleri çağır
                scan_results = self._run_quick_scan()
            elif scan_type == "full":
                # Tam tarama için tüm modülleri çağır
                scan_results = self._run_full_scan()
            else:
                # Özel tarama
                scan_results = self._run_custom_scan(scan_config)
            
            # Tarama kaydını güncelle
            self.repository.update_scan_record(
                scan_id, 
                status="completed",
                results=scan_results
            )
            
            # Tarama tamamlandı olayını oluştur
            self.process_event(Event(
                type=EventType.SCAN_COMPLETE,
                source="core.engine",
                severity=EventSeverity.INFO,
                details={
                    "scan_id": scan_id,
                    "scan_type": scan_type,
                    "results": scan_results
                }
            ))
            
            self.logger.info(f"Tarama tamamlandı: {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Tarama sırasında hata: {e}", exc_info=True)
            
            # Tarama kaydını hata olarak güncelle
            self.repository.update_scan_record(
                scan_id, 
                status="error",
                error_details=str(e)
            )
    
    def _run_quick_scan(self) -> Dict[str, Any]:
        """
        Hızlı sistem taraması yürütür
        
        Returns:
            Dict[str, Any]: Tarama sonuçları
        """
        results = {"threats": [], "scanned_items": 0}
        
        # Anti-malware modülünü kullan
        if "antimalware" in self.protection_modules:
            module = self.protection_modules["antimalware"]
            scan_result = module.run_quick_scan()
            results["threats"].extend(scan_result.get("threats", []))
            results["scanned_items"] += scan_result.get("scanned_items", 0)
        
        # Kritik sistem dosyalarını kontrol et
        if "auto_repair" in self.remediation_modules:
            module = self.remediation_modules["auto_repair"]
            integrity_result = module.check_system_integrity()
            results["integrity_issues"] = integrity_result.get("issues", [])
        
        return results
    
    def _run_full_scan(self) -> Dict[str, Any]:
        """
        Tam sistem taraması yürütür
        
        Returns:
            Dict[str, Any]: Tarama sonuçları
        """
        results = {"threats": [], "scanned_items": 0}
        
        # Anti-malware modülünü kullan
        if "antimalware" in self.protection_modules:
            module = self.protection_modules["antimalware"]
            scan_result = module.run_full_scan()
            results["threats"].extend(scan_result.get("threats", []))
            results["scanned_items"] += scan_result.get("scanned_items", 0)
        
        # Ağ taraması yap
        if "network_monitor" in self.monitoring_modules:
            module = self.monitoring_modules["network_monitor"]
            network_result = module.scan_network()
            results["network_issues"] = network_result.get("issues", [])
        
        # Sistem bütünlüğünü kontrol et
        if "auto_repair" in self.remediation_modules:
            module = self.remediation_modules["auto_repair"]
            integrity_result = module.check_system_integrity(deep_scan=True)
            results["integrity_issues"] = integrity_result.get("issues", [])
        
        return results
    
    def _run_custom_scan(self, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Özel yapılandırmalı tarama yürütür
        
        Args:
            scan_config (Dict[str, Any]): Tarama yapılandırması
            
        Returns:
            Dict[str, Any]: Tarama sonuçları
        """
        # Özel tarama mantığı buraya gelecek
        # Şimdilik basit bir tarama yap
        return self._run_quick_scan()
    
    def _get_protection_status(self) -> Dict[str, Any]:
        """
        Genel koruma durumunu döndürür
        
        Returns:
            Dict[str, Any]: Koruma durumu bilgileri
        """
        status = {
            "overall": "protected",
            "antimalware": True,
            "firewall": True,
            "network": True,
            "updates": True
        }
        
        # Koruma durumunu kontrol et
        active_threats = self.repository.get_active_threat_count()
        if active_threats > 0:
            status["overall"] = "at_risk"
        
        # Modül durumlarını kontrol et
        if "antimalware" in self.protection_modules:
            status["antimalware"] = self.protection_modules["antimalware"].is_active()
        
        if "firewall" in self.protection_modules:
            status["firewall"] = self.protection_modules["firewall"].is_active()
        
        if "network_monitor" in self.monitoring_modules:
            status["network"] = self.monitoring_modules["network_monitor"].is_active()
        
        if "update_manager" in self.remediation_modules:
            status["updates"] = self.remediation_modules["update_manager"].is_system_updated()
            
        return status
    
    def _get_all_module_status(self) -> Dict[str, bool]:
        """
        Tüm modüllerin durum bilgisini döndürür
        
        Returns:
            Dict[str, bool]: Modül durum bilgileri
        """
        status = {}
        
        # Tüm modülleri birleştir
        all_modules = {
            **self.protection_modules,
            **self.monitoring_modules,
            **self.remediation_modules
        }
        
        # Her modülün durumunu al
        for name, module in all_modules.items():
            status[name] = module.is_active()
        
        return status
    
    def _handle_scan_complete(self, event: Event):
        """
        Tarama tamamlandı olayını işler
        
        Args:
            event (Event): İşlenecek olay
        """
        scan_id = event.details.get("scan_id")
        self.logger.debug(f"Tarama tamamlandı işleniyor: {scan_id}")
        
        # Sonuçları analiz et ve gerekirse otomatik eylemler yap
        scan_results = event.details.get("results", {})
        threats = scan_results.get("threats", [])
        
        if threats:
            self.logger.info(f"{len(threats)} tehdit tespit edildi")
            # Tehditleri işle
            for threat_data in threats:
                threat = Threat.from_dict(threat_data)
                self._handle_threat(threat)
    
    def _handle_system_change(self, event: Event):
        """
        Sistem değişikliği olayını işler
        
        Args:
            event (Event): İşlenecek olay
        """
        self.logger.debug(f"Sistem değişikliği işleniyor: {event.id}")
        # Sistem değişikliğine özel işlemler buraya gelecek
    
    def _handle_network_alert(self, event: Event):
        """
        Ağ uyarısı olayını işler
        
        Args:
            event (Event): İşlenecek olay
        """
        self.logger.debug(f"Ağ uyarısı işleniyor: {event.id}")
        # Ağ uyarısına özel işlemler buraya gelecek