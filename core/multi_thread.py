"""
MapSQL - Motor Multi-Threading Avanzado
Soporte para cientos de peticiones simultáneas con control de recursos
"""

import threading
import queue
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable
import random

class AdvancedThreadPool:
    """Pool de hilos inteligente con rate limiting y retry automático"""
    
    def __init__(self, max_workers=10, rate_limit=0, max_retries=3):
        """
        Args:
            max_workers: Número máximo de hilos concurrentes
            rate_limit: Segundos entre peticiones (0 = sin límite)
            max_retries: Reintentos automáticos por fallo
        """
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.max_retries = max_retries
        self.results = []
        self.errors = []
        self._last_request_time = 0
        self._lock = threading.Lock()
        
    def execute(self, tasks: List[Dict], worker_func: Callable) -> List[Any]:
        """
        Ejecuta múltiples tareas en paralelo
        
        Args:
            tasks: Lista de diccionarios con argumentos para worker_func
            worker_func: Función que ejecuta la tarea
            
        Returns:
            Lista de resultados en el mismo orden que las tareas
        """
        results = [None] * len(tasks)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit todas las tareas
            future_to_index = {}
            for idx, task in enumerate(tasks):
                future = executor.submit(self._execute_with_retry, worker_func, task, idx)
                future_to_index[future] = idx
            
            # Recolectar resultados
            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                try:
                    result = future.result()
                    results[idx] = result
                    self.results.append(result)
                except Exception as e:
                    self.errors.append((idx, str(e)))
                    results[idx] = None
                    
        return results
    
    def _execute_with_retry(self, worker_func, task, task_id):
        """Ejecuta con reintentos y rate limiting"""
        for attempt in range(self.max_retries):
            try:
                # Rate limiting
                if self.rate_limit > 0:
                    with self._lock:
                        now = time.time()
                        elapsed = now - self._last_request_time
                        if elapsed < self.rate_limit:
                            time.sleep(self.rate_limit - elapsed)
                        self._last_request_time = time.time()
                
                return worker_func(**task)
                
            except Exception as e:
                if attempt == self.max_retries - 1:
                    raise e
                time.sleep(2 ** attempt)  # Backoff exponencial
        
    def get_stats(self):
        """Estadísticas de ejecución"""
        return {
            'total_tasks': len(self.results) + len(self.errors),
            'successful': len(self.results),
            'failed': len(self.errors),
            'success_rate': (len(self.results) / (len(self.results) + len(self.errors))) * 100 if (self.results or self.errors) else 0
        }


class PayloadDistributor:
    """Distribuye payloads entre hilos para maximizar cobertura"""
    
    def __init__(self, payloads: List[str], targets: List[str]):
        self.payloads = payloads
        self.targets = targets
        self.queue = queue.Queue()
        self._setup_queue()
        
    def _setup_queue(self):
        """Organiza combinaciones payload-target"""
        for payload in self.payloads:
            for target in self.targets:
                self.queue.put({
                    'payload': payload,
                    'target': target,
                    'timestamp': time.time()
                })
    
    def get_batch(self, batch_size=10) -> List[Dict]:
        """Obtiene un lote de tareas"""
        batch = []
        for _ in range(min(batch_size, self.queue.qsize())):
            try:
                batch.append(self.queue.get_nowait())
            except queue.Empty:
                break
        return batch
    
    def remaining(self) -> int:
        return self.queue.qsize()


# Ejemplo de worker para pruebas SQLi
def sqli_worker(url: str, param: str, payload: str, session: requests.Session) -> Dict:
    """Worker que prueba un payload específico"""
    parsed_url = f"{url}?{param}={payload}"
    
    try:
        start_time = time.time()
        response = session.get(parsed_url, timeout=5)
        elapsed = time.time() - start_time
        
        return {
            'url': parsed_url,
            'payload': payload,
            'status_code': response.status_code,
            'response_time': elapsed,
            'response_length': len(response.text),
            'success': True
        }
    except Exception as e:
        return {
            'url': parsed_url,
            'payload': payload,
            'error': str(e),
            'success': False
        }
