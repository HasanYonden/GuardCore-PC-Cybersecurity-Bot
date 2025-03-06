#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GuardCore - PC Siber Güvenlik Botu
-----------------------------------
Bu modül, GuardCore PC Siber Güvenlik Botunun ana giriş noktasıdır.
Tüm alt sistemleri başlatır ve koordine eder.

Yazarlar: GuardCore Dev Team
Lisans: MIT
Versiyon: 0.1.0
"""

import os
import sys
import time
import signal
import argparse
import logging
from pathlib import Path

# GuardCore modüllerini içe aktar
from guardcore.core.engine import CoreEngine
from guardcore.config.settings import Settings
from guardcore.utils.logger import setup_logging
from guardcore.ui.api.server import APIServer

class GuardCore:
    """GuardCore ana uygulama sınıfı"""
    
    def __init__(self, config_path=None, debug=False):
        """
        GuardCore uygulamasını başlatır.
        
        Args:
            config_path (str, optional): Yapılandırma dosyasının yolu
            debug (bool, optional): Hata ayıklama modunu aktifleştirir
        """
        # Uygulama yollarını ayarla
        self.base_dir = Path(__file__).resolve().parent
        
        # Loglama sistemini kur
        log_level = logging.DEBUG if debug else logging.INFO
        self.logger = setup_logging(log_level)
        self.logger.info("GuardCore başlatılıyor...")
        
        # Yapılandırmayı yükle
        self.settings = Settings(config_path)
        self.logger.debug(f"Yapılandırma yüklendi: {config_path or 'default'}")
        
        # Ana motoru başlat
        self.engine = CoreEngine(self.settings)
        
        # API sunucusunu başlat (UI ile iletişim için)
        self.api_server = APIServer(self.engine, self.settings)
        
        # Sinyal işleyicilerini kaydet
        signal.signal(signal.SIGINT, self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)
        
        self.running = False
        self.logger.info("GuardCore başlatma işlemi tamamlandı")
    
    def start(self):
        """Tüm GuardCore servislerini başlatır"""
        self.logger.info("GuardCore servisleri başlatılıyor...")
        self.running = True
        
        try:
            # Ana motoru başlat
            self.engine.start()
            
            # API sunucusunu başlat
            self.api_server.start()
            
            # Ana UI'ı başlat (geliştirme aşamasında isteğe bağlı)
            if self.settings.get("ui.auto_start", True):
                self._start_ui()
            
            self.logger.info("GuardCore başarıyla başlatıldı")
            
            # Ana döngüde bekle
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            self.logger.error(f"GuardCore başlatma hatası: {e}", exc_info=True)
            self.stop()
            raise
    
    def stop(self):
        """Tüm GuardCore servislerini durdurur"""
        self.logger.info("GuardCore servisleri durduruluyor...")
        self.running = False
        
        # API sunucusunu durdur
        if self.api_server:
            self.api_server.stop()
        
        # Ana motoru durdur
        if self.engine:
            self.engine.stop()
        
        self.logger.info("GuardCore servisleri durduruldu")
    
    def _start_ui(self):
        """Electron UI'ı başlatır"""
        self.logger.info("Kullanıcı arayüzü başlatılıyor...")
        # Electron uygulamasını başlatma kodu buraya gelecek
        # Geliştirme aşamasında bu kısmı atla
        pass
    
    def _handle_exit(self, signum, frame):
        """Sinyal işleyicisi - temiz çıkış sağlar"""
        self.logger.info(f"Çıkış sinyali alındı: {signum}")
        self.stop()


def parse_arguments():
    """Komut satırı argümanlarını ayrıştırır"""
    parser = argparse.ArgumentParser(description='GuardCore PC Siber Güvenlik Botu')
    parser.add_argument('-c', '--config', 
                        help='Yapılandırma dosyasının yolu')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Hata ayıklama modunu aktifleştirir')
    parser.add_argument('-s', '--service', action='store_true',
                        help='Servis modu (UI olmadan çalışır)')
    return parser.parse_args()


def main():
    """Ana program giriş noktası"""
    args = parse_arguments()
    
    # GuardCore örneğini oluştur
    guard_core = GuardCore(
        config_path=args.config,
        debug=args.debug
    )
    
    try:
        # GuardCore'u başlat
        guard_core.start()
    except KeyboardInterrupt:
        print("\nKullanıcı tarafından durduruldu")
    except Exception as e:
        print(f"Kritik hata: {e}")
        return 1
    finally:
        # Program sonlandırılırken temiz kapatma
        guard_core.stop()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())