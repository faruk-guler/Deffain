#!/usr/bin/env python3
"""
Deffain OpenSource Firewall v2.0
Güvenli ve gelişmiş Linux firewall yönetim aracı
"""

import subprocess
import sys
import logging
import re
import json
import os
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum

# Logging yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/deffain.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    BOTH = "both"

class Action(Enum):
    ACCEPT = "accept"
    DROP = "drop"
    REJECT = "reject"

@dataclass
class FirewallRule:
    """Firewall kuralı veri yapısı"""
    port: int
    protocol: Protocol
    action: Action
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    comment: Optional[str] = None

class InputValidator:
    """Girdi doğrulama sınıfı"""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """IP adresini doğrula"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """CIDR notasyonunu doğrula"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """Port numarasını doğrula"""
        try:
            p = int(port)
            return 1 <= p <= 65535
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_protocol(protocol: str) -> bool:
        """Protokol adını doğrula"""
        return protocol.lower() in ['tcp', 'udp', 'both']
    
    @staticmethod
    def sanitize_string(text: str) -> str:
        """String'i güvenli hale getir"""
        # Sadece güvenli karakterlere izin ver
        allowed_chars = re.compile(r'^[a-zA-Z0-9\.\-_/:\s]+$')
        if not allowed_chars.match(text):
            raise ValueError(f"Güvenli olmayan karakterler: {text}")
        return text.strip()

class ConfigManager:
    """Yapılandırma yöneticisi"""
    
    def __init__(self, config_path: str = "/etc/deffain/config.json"):
        self.config_path = Path(config_path)
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Yapılandırmayı yükle"""
        default_config = {
            "default_policy": "drop",
            "log_level": "INFO",
            "backup_rules": True,
            "auto_save": True,
            "trusted_networks": ["127.0.0.0/8", "::1/128"],
            "blocked_networks": [],
            "rate_limiting": {
                "enabled": True,
                "connections_per_minute": 100
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # Varsayılan değerlerle birleştir
                    default_config.update(config)
                    return default_config
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Yapılandırma dosyası okunamadı: {e}, varsayılan ayarlar kullanılıyor")
        
        return default_config
    
    def save_config(self) -> bool:
        """Yapılandırmayı kaydet"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            return True
        except IOError as e:
            logger.error(f"Yapılandırma kaydedilemedi: {e}")
            return False

class DeffainFirewall:
    """Ana firewall sınıfı"""
    
    def __init__(self):
        self.check_root()
        self.check_nftables()
        self.validator = InputValidator()
        self.config_manager = ConfigManager()
        self.table_name = "deffain_filter"
        self.input_chain = "deffain_input"
        self.output_chain = "deffain_output"
        self.forward_chain = "deffain_forward"
        self.rules_file = "/etc/deffain/rules.json"
        self.setup_nftables()
        self.load_saved_rules()
    
    def check_root(self) -> None:
        """Root yetkisini kontrol et"""
        try:
            result = subprocess.run(['id', '-u'], capture_output=True, text=True, check=True)
            if result.stdout.strip() != '0':
                logger.error("Deffain root yetkisi gerektirir!")
                sys.exit(1)
        except subprocess.CalledProcessError:
            logger.error("Yetki kontrolü başarısız!")
            sys.exit(1)
    
    def check_nftables(self) -> None:
        """nftables kurulumunu kontrol et"""
        try:
            subprocess.run(['nft', '--version'], capture_output=True, check=True)
            logger.info("nftables bulundu")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("nftables yüklü değil! Kurulum: apt-get install nftables")
            sys.exit(1)
    
    def run_nft_command(self, command: List[str]) -> bool:
        """Güvenli nftables komut çalıştırma"""
        try:
            # Komut güvenlik kontrolü
            if not all(isinstance(arg, str) for arg in command):
                raise ValueError("Güvenli olmayan komut parametresi")
            
            # Komut logging
            logger.debug(f"NFT komutu: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                timeout=30  # Timeout eklendi
            )
            
            if result.stdout:
                logger.debug(f"NFT çıktı: {result.stdout}")
            
            return True
            
        except subprocess.TimeoutExpired:
            logger.error("NFT komutu timeout")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"NFT komutu başarısız: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Beklenmeyen hata: {e}")
            return False
    
    def setup_nftables(self) -> bool:
        """nftables yapılandırmasını kur"""
        commands = [
            # Tabloyu oluştur
            ['nft', 'add', 'table', 'inet', self.table_name],
            
            # Chain'leri oluştur
            ['nft', 'add', 'chain', 'inet', self.table_name, self.input_chain, 
             '{ type filter hook input priority 0; policy drop; }'],
            ['nft', 'add', 'chain', 'inet', self.table_name, self.output_chain, 
             '{ type filter hook output priority 0; policy accept; }'],
            ['nft', 'add', 'chain', 'inet', self.table_name, self.forward_chain, 
             '{ type filter hook forward priority 0; policy drop; }'],
            
            # Temel kurallar
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain, 
             'iifname "lo" accept'],
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain, 
             'ct state established,related accept'],
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain, 
             'ct state invalid drop'],
            
            # ICMP izin ver
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain, 
             'ip protocol icmp accept'],
            ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain, 
             'ip6 nexthdr icmpv6 accept'],
        ]
        
        success = True
        for cmd in commands:
            if not self.run_nft_command(cmd):
                success = False
        
        if success:
            logger.info("Firewall temel yapılandırması tamamlandı")
        else:
            logger.error("Firewall yapılandırması başarısız")
        
        return success
    
    def add_rule(self, rule: FirewallRule) -> bool:
        """Firewall kuralı ekle"""
        try:
            # Girdi doğrulama
            if not self.validator.validate_port(rule.port):
                raise ValueError(f"Geçersiz port: {rule.port}")
            
            if rule.source_ip:
                if not (self.validator.validate_ip(rule.source_ip) or 
                       self.validator.validate_cidr(rule.source_ip)):
                    raise ValueError(f"Geçersiz kaynak IP: {rule.source_ip}")
            
            if rule.destination_ip:
                if not (self.validator.validate_ip(rule.destination_ip) or 
                       self.validator.validate_cidr(rule.destination_ip)):
                    raise ValueError(f"Geçersiz hedef IP: {rule.destination_ip}")
            
            # Kural oluştur
            protocols = []
            if rule.protocol == Protocol.TCP:
                protocols = ['tcp']
            elif rule.protocol == Protocol.UDP:
                protocols = ['udp']
            elif rule.protocol == Protocol.BOTH:
                protocols = ['tcp', 'udp']
            
            success = True
            for proto in protocols:
                nft_rule = self._build_nft_rule(rule, proto)
                if not self.run_nft_command(nft_rule):
                    success = False
            
            if success:
                self.save_rule(rule)
                logger.info(f"Kural eklendi: {rule}")
            
            return success
            
        except ValueError as e:
            logger.error(f"Kural ekleme hatası: {e}")
            return False
    
    def _build_nft_rule(self, rule: FirewallRule, protocol: str) -> List[str]:
        """NFT kuralını oluştur"""
        nft_rule = ['nft', 'add', 'rule', 'inet', self.table_name, self.input_chain]
        
        # Kaynak IP
        if rule.source_ip:
            if ':' in rule.source_ip:  # IPv6
                nft_rule.extend(['ip6', 'saddr', rule.source_ip])
            else:  # IPv4
                nft_rule.extend(['ip', 'saddr', rule.source_ip])
        
        # Hedef IP
        if rule.destination_ip:
            if ':' in rule.destination_ip:  # IPv6
                nft_rule.extend(['ip6', 'daddr', rule.destination_ip])
            else:  # IPv4
                nft_rule.extend(['ip', 'daddr', rule.destination_ip])
        
        # Protokol ve port
        nft_rule.extend([protocol, 'dport', str(rule.port)])
        
        # Aksiyon
        nft_rule.append(rule.action.value)
        
        # Yorum
        if rule.comment:
            nft_rule.extend(['comment', f'"{rule.comment}"'])
        
        return nft_rule
    
    def remove_rule(self, port: int, protocol: str = "tcp", source_ip: Optional[str] = None) -> bool:
        """Kural sil"""
        try:
            # Kuralı bul ve sil
            rules = self.list_rules()
            handle = self._find_rule_handle(port, protocol, source_ip)
            
            if handle:
                cmd = ['nft', 'delete', 'rule', 'inet', self.table_name, self.input_chain, 'handle', handle]
                if self.run_nft_command(cmd):
                    logger.info(f"Kural silindi: port {port}/{protocol}")
                    return True
            
            logger.warning(f"Kural bulunamadı: port {port}/{protocol}")
            return False
            
        except Exception as e:
            logger.error(f"Kural silme hatası: {e}")
            return False
    
    def _find_rule_handle(self, port: int, protocol: str, source_ip: Optional[str]) -> Optional[str]:
        """Kural handle'ını bul"""
        try:
            result = subprocess.run(
                ['nft', 'list', 'chain', 'inet', self.table_name, self.input_chain, '-a'],
                capture_output=True, text=True, check=True
            )
            
            # Handle'ları parse et
            for line in result.stdout.split('\n'):
                if f'{protocol} dport {port}' in line and 'handle' in line:
                    if not source_ip or source_ip in line:
                        # Handle numarasını çıkar
                        handle_match = re.search(r'handle (\d+)', line)
                        if handle_match:
                            return handle_match.group(1)
            
            return None
            
        except subprocess.CalledProcessError:
            return None
    
    def list_rules(self) -> str:
        """Kuralları listele"""
        try:
            result = subprocess.run(
                ['nft', 'list', 'table', 'inet', self.table_name],
                capture_output=True, text=True, check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            logger.error(f"Kural listeleme hatası: {e}")
            return "Kurallar listelenemedi"
    
    def save_rule(self, rule: FirewallRule) -> bool:
        """Kuralı dosyaya kaydet"""
        try:
            rules_path = Path(self.rules_file)
            rules_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Mevcut kuralları yükle
            rules = []
            if rules_path.exists():
                with open(rules_path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
            
            # Yeni kuralı ekle
            rule_dict = {
                'port': rule.port,
                'protocol': rule.protocol.value,
                'action': rule.action.value,
                'source_ip': rule.source_ip,
                'destination_ip': rule.destination_ip,
                'comment': rule.comment
            }
            rules.append(rule_dict)
            
            # Kaydet
            with open(rules_path, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            logger.error(f"Kural kaydetme hatası: {e}")
            return False
    
    def load_saved_rules(self) -> bool:
        """Kaydedilmiş kuralları yükle"""
        try:
            rules_path = Path(self.rules_file)
            if not rules_path.exists():
                return True
            
            with open(rules_path, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
            
            for rule_data in rules_data:
                rule = FirewallRule(
                    port=rule_data['port'],
                    protocol=Protocol(rule_data['protocol']),
                    action=Action(rule_data['action']),
                    source_ip=rule_data.get('source_ip'),
                    destination_ip=rule_data.get('destination_ip'),
                    comment=rule_data.get('comment')
                )
                self.add_rule(rule)
            
            logger.info(f"{len(rules_data)} kural yüklendi")
            return True
            
        except Exception as e:
            logger.error(f"Kural yükleme hatası: {e}")
            return False
    
    def enable_firewall(self) -> bool:
        """Firewall'u etkinleştir"""
        return self.setup_nftables()
    
    def disable_firewall(self) -> bool:
        """Firewall'u devre dışı bırak"""
        return self.run_nft_command(['nft', 'delete', 'table', 'inet', self.table_name])
    
    def backup_rules(self, backup_path: str) -> bool:
        """Kuralları yedekle"""
        try:
            result = subprocess.run(
                ['nft', 'list', 'ruleset'],
                capture_output=True, text=True, check=True
            )
            
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(result.stdout)
            
            logger.info(f"Kurallar yedeklendi: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Yedekleme hatası: {e}")
            return False
    
    def restore_rules(self, backup_path: str) -> bool:
        """Kuralları geri yükle"""
        try:
            with open(backup_path, 'r', encoding='utf-8') as f:
                rules_content = f.read()
            
            # Mevcut kuralları temizle
            self.run_nft_command(['nft', 'flush', 'ruleset'])
            
            # Yedek kuralları yükle
            process = subprocess.Popen(
                ['nft', '-f', '-'],
                stdin=subprocess.PIPE,
                text=True
            )
            process.communicate(input=rules_content)
            
            if process.returncode == 0:
                logger.info(f"Kurallar geri yüklendi: {backup_path}")
                return True
            else:
                logger.error("Kural geri yükleme başarısız")
                return False
                
        except Exception as e:
            logger.error(f"Geri yükleme hatası: {e}")
            return False

class CommandParser:
    """Komut ayrıştırıcısı"""
    
    def __init__(self, firewall: DeffainFirewall):
        self.firewall = firewall
        self.validator = InputValidator()
    
    def parse_command(self, command: str) -> bool:
        """Komutu ayrıştır ve çalıştır"""
        try:
            command = command.strip().lower()
            
            # Port komutları
            if command.startswith('port'):
                return self.parse_port_command(command)
            
            # Durum komutları
            elif command == 'status':
                print(self.firewall.list_rules())
                return True
            
            elif command == 'enable' or command == 'on':
                return self.firewall.enable_firewall()
            
            elif command == 'disable' or command == 'off':
                return self.firewall.disable_firewall()
            
            # Yedekleme komutları
            elif command.startswith('backup'):
                parts = command.split()
                if len(parts) > 1:
                    return self.firewall.backup_rules(parts[1])
                else:
                    return self.firewall.backup_rules('/tmp/deffain_backup.nft')
            
            elif command.startswith('restore'):
                parts = command.split()
                if len(parts) > 1:
                    return self.firewall.restore_rules(parts[1])
                else:
                    print("Yedek dosya yolu belirtilmeli")
                    return False
            
            elif command == 'help':
                self.show_help()
                return True
            
            else:
                logger.error(f"Bilinmeyen komut: {command}")
                self.show_help()
                return False
                
        except Exception as e:
            logger.error(f"Komut ayrıştırma hatası: {e}")
            return False
    
    def parse_port_command(self, command: str) -> bool:
        """Port komutunu ayrıştır"""
        # port open/close 80 tcp/udp [from/to ip/cidr] [comment]
        pattern = r'port\s+(open|close)\s+(\d+)(?:\s+(tcp|udp|both))?(?:\s+(from|to)\s+(\S+))?(?:\s+comment\s+"([^"]*)")?'
        match = re.match(pattern, command, re.IGNORECASE)
        
        if not match:
            logger.error("Geçersiz port komutu formatı")
            return False
        
        action_str, port_str, protocol_str, direction, ip_str, comment = match.groups()
        
        # Varsayılan değerler
        protocol_str = protocol_str or 'tcp'
        
        # Doğrulama
        if not self.validator.validate_port(port_str):
            logger.error(f"Geçersiz port: {port_str}")
            return False
        
        if not self.validator.validate_protocol(protocol_str):
            logger.error(f"Geçersiz protokol: {protocol_str}")
            return False
        
        if ip_str:
            if not (self.validator.validate_ip(ip_str) or self.validator.validate_cidr(ip_str)):
                logger.error(f"Geçersiz IP/CIDR: {ip_str}")
                return False
        
        # Kural oluştur
        port = int(port_str)
        protocol = Protocol(protocol_str.lower())
        action = Action.ACCEPT if action_str.lower() == 'open' else Action.DROP
        
        source_ip = ip_str if direction == 'from' else None
        destination_ip = ip_str if direction == 'to' else None
        
        rule = FirewallRule(
            port=port,
            protocol=protocol,
            action=action,
            source_ip=source_ip,
            destination_ip=destination_ip,
            comment=comment
        )
        
        return self.firewall.add_rule(rule)
    
    def show_help(self):
        """Yardım mesajını göster"""
        help_text = """
╔══════════════════════════════════════════════════════════════╗
║                  Deffain Firewall v2.0                      ║
║                Güvenli Firewall Yönetimi                     ║
╚══════════════════════════════════════════════════════════════╝

TEMEL KOMUTLAR:
  enable/on                 -> Firewall'u etkinleştir
  disable/off               -> Firewall'u devre dışı bırak
  status                    -> Firewall durumunu göster
  help                      -> Bu yardım mesajını göster

PORT YÖNETİMİ:
  port open <port> [protokol] [from/to ip] [comment "açıklama"]
  port close <port> [protokol] [from/to ip] [comment "açıklama"]
  
  Protokol: tcp, udp, both (varsayılan: tcp)
  IP: Tek IP (1.2.3.4) veya CIDR (192.168.1.0/24)

ÖRNEKLER:
  port open 22                              # SSH için TCP/22 aç
  port open 80 tcp                          # HTTP için TCP/80 aç
  port open 53 both                         # DNS için TCP/UDP 53 aç
  port open 22 tcp from 192.168.1.0/24     # SSH'yi sadece yerel ağa aç
  port open 443 tcp comment "HTTPS Server"  # Açıklama ile HTTPS aç
  port close 23                             # Telnet'i kapat
  
YEDEKLEME:
  backup [dosya_yolu]       # Kuralları yedekle
  restore <dosya_yolu>      # Kuralları geri yükle

KULLANIM:
  sudo python3 deffain.py 'port open 22 tcp'
  sudo python3 deffain.py 'status'
  sudo python3 deffain.py 'backup /home/user/firewall.bak'
"""
        print(help_text)

def main():
    """Ana fonksiyon"""
    if len(sys.argv) < 2:
        print("Deffain OpenSource Firewall v2.0")
        print("Kullanım: sudo python3 deffain.py 'komut'")
        print("Yardım: sudo python3 deffain.py 'help'")
        sys.exit(1)
    
    try:
        firewall = DeffainFirewall()
        parser = CommandParser(firewall)
        command = ' '.join(sys.argv[1:])
        
        if parser.parse_command(command):
            logger.info("Komut başarıyla tamamlandı")
        else:
            logger.error("Komut başarısız")
            sys.exit(1)
            
    except KeyboardInterrupt:
        logger.info("İşlem kullanıcı tarafından iptal edildi")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Beklenmeyen hata: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
