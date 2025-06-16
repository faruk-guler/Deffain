#!/usr/bin/env python3
"""
Deffain OpenSource Firewall
A simple and powerful firewall management tool for Linux servers
"""

import subprocess
import sys
import logging
import re

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Deffain:
    def __init__(self):
        self.check_root()
        self.check_nftables()
        self.table_name = "filter"
        self.chain_name = "input"
        self.setup_nftables()

    def check_root(self):
        """Check if script is running with root privileges"""
        if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
            logger.error("Deffain root yetkisi gerektirir!")
            sys.exit(1)

    def check_nftables(self):
        """Check if nftables is installed"""
        try:
            subprocess.run(['nft', 'list', 'ruleset'], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            logger.error("nftables yüklü değil! Lütfen 'apt-get install nftables' komutu ile yükleyin.")
            sys.exit(1)

    def run_command(self, command):
        """Execute shell command"""
        try:
            subprocess.run(command, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Deffain Hatası: {e}")
            return False

    def setup_nftables(self):
        """Setup initial nftables configuration"""
        # Tablo oluştur
        self.run_command(['nft', 'add', 'table', 'inet', self.table_name])
        # Input chain oluştur
        self.run_command(['nft', 'add', 'chain', 'inet', self.table_name, self.chain_name, '{ type filter hook input priority 0 \; }'])
        # Varsayılan politikayı drop yap
        self.run_command(['nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 'ct state established,related accept'])
        self.run_command(['nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 'ct state invalid drop'])

    def parse_command(self, command):
        """Parse simple firewall commands"""
        # Port açma/kapama komutları
        port_pattern = r'port\s+(open|close)\s+(\d+)(?:\s*([<>])\s*(\S+))?'
        port_match = re.match(port_pattern, command, re.IGNORECASE)
        
        if port_match:
            action, port, direction, target = port_match.groups()
            
            if action.lower() == 'open':
                if direction == '>':
                    # Belirli bir IP'ye port açma
                    return self.run_command(['nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 
                                           f'ip daddr {target} tcp dport {port} accept'])
                elif direction == '<':
                    # Belirli bir IP'den gelen trafiğe port açma
                    return self.run_command(['nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 
                                           f'ip saddr {target} tcp dport {port} accept'])
                else:
                    # Herkese port açma
                    return self.run_command(['nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 
                                           f'tcp dport {port} accept'])
            else:  # close
                if direction == '>':
                    # Belirli bir IP'ye port kapatma
                    return self.run_command(['nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 
                                           f'ip daddr {target} tcp dport {port} drop'])
                elif direction == '<':
                    # Belirli bir IP'den gelen trafiği engelleme
                    return self.run_command(['nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 
                                           f'ip saddr {target} tcp dport {port} drop'])
                else:
                    # Herkese port kapatma
                    return self.run_command(['nft', 'add', 'rule', 'inet', self.table_name, self.chain_name, 
                                           f'tcp dport {port} drop'])
        
        # Firewall durumu
        elif command.lower() == 'status':
            return self.run_command(['nft', 'list', 'ruleset'])
        
        # Firewall açma/kapama
        elif command.lower() == 'on':
            return self.run_command(['nft', 'flush', 'ruleset']) and self.setup_nftables()
        elif command.lower() == 'off':
            return self.run_command(['nft', 'flush', 'ruleset'])
        
        # Yardım
        elif command.lower() == 'help':
            self.show_help()
            return True
        
        else:
            logger.error("Geçersiz komut! Yardım için 'help' yazın.")
            return False

    def show_help(self):
        """Show help message"""
        help_text = """
Deffain OpenSource Firewall - Kullanım Kılavuzu

Komutlar:
  port open 22          -> 22 portunu herkese aç
  port close 22         -> 22 portunu herkese kapat
  port open 22 > 1.2.3.4 -> 22 portunu sadece 1.2.3.4 IP'sine aç
  port open 22 < 1.2.3.4 -> 1.2.3.4 IP'sinden gelen 22 portuna izin ver
  port close 22 > 1.2.3.4 -> 22 portunu 1.2.3.4 IP'sine kapat
  port close 22 < 1.2.3.4 -> 1.2.3.4 IP'sinden gelen 22 portunu engelle
  status                -> Firewall durumunu göster
  on                    -> Firewall'u aç
  off                   -> Firewall'u kapat
  help                  -> Bu yardım mesajını göster

Örnekler:
  sudo ./deffain.py 'port open 22'     # SSH için
  sudo ./deffain.py 'port open 80'     # HTTP için
  sudo ./deffain.py 'port open 443'    # HTTPS için
  sudo ./deffain.py 'status'           # Durumu kontrol et
"""
        print(help_text)

def main():
    if len(sys.argv) < 2:
        print("Deffain OpenSource Firewall")
        print("Kullanım: sudo ./deffain.py 'komut'")
        print("Örnek: sudo ./deffain.py 'port open 22'")
        print("Yardım için: sudo ./deffain.py 'help'")
        sys.exit(1)

    firewall = Deffain()
    command = ' '.join(sys.argv[1:])
    firewall.parse_command(command)

if __name__ == '__main__':
    main() 