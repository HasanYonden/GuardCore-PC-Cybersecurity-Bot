guardcore/

├── __init__.py

├── config/
│   ├── __init__.py
│   ├── settings.py
│   └── default_config.yaml
├── core/
│   ├── __init__.py
│   ├── engine.py
│   ├── scheduler.py
│   ├── resource_manager.py
│   └── threat_analyzer.py
├── modules/
│   ├── __init__.py
│   ├── protection/
│   │   ├── __init__.py
│   │   ├── antimalware.py
│   │   ├── firewall.py
│   │   └── zeroday.py
│   ├── monitoring/
│   │   ├── __init__.py
│   │   ├── network_monitor.py
│   │   ├── behavior_analyzer.py
│   │   └── data_monitor.py
│   ├── remediation/
│   │   ├── __init__.py
│   │   ├── auto_repair.py
│   │   ├── update_manager.py
│   │   └── quarantine.py
│   └── common/
│       ├── __init__.py
│       ├── event.py
│       └── threat.py
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   ├── crypto.py
│   └── system_info.py
├── db/
│   ├── __init__.py
│   ├── models.py
│   └── repository.py
├── ui/
│   ├── electron/
│   │   ├── package.json
│   │   ├── main.js
│   │   └── src/
│   │       ├── components/
│   │       └── pages/
│   └── api/
│       ├── __init__.py
│       └── server.py
├── tests/
│   ├── __init__.py
│   ├── test_protection.py
│   ├── test_monitoring.py
│   └── test_remediation.py
├── main.py
├── requirements.txt
└── setup.py# GuardCore-PC-Cybersecurity-Bot
