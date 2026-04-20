"""
MapSQL - Detector de SQLi con Machine Learning
Clasificación inteligente de vulnerabilidades
"""

import re
import math
from typing import Dict, List, Tuple
from collections import Counter
import json

class FeatureExtractor:
    """Extrae características de las respuestas HTTP para ML"""
    
    @staticmethod
    def extract_features(response_text: str, status_code: int, response_time: float) -> Dict:
        """Extrae vector de características para clasificación"""
        features = {
            'status_code': status_code,
            'response_time': response_time,
            'length': len(response_text),
            'sql_errors': 0,
            'dbms_indicators': 0,
            'special_chars_ratio': 0,
            'entropy': 0,
            'has_union': 0,
            'has_order_by': 0,
            'has_comment': 0
        }
        
        # Patrones de errores SQL comunes
        sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"PostgreSQL.*ERROR",
            r"ORA-[0-9]{5}",
            r"Microsoft.*ODBC.*SQL",
            r"SQLite.*Exception",
            r"Unclosed quotation mark"
        ]
        
        features['sql_errors'] = sum(1 for pattern in sql_error_patterns if re.search(pattern, response_text, re.I))
        
        # Indicadores de DBMS
        dbms_indicators = {
            'mysql': ['mysql', 'maria', 'mySQL', 'mysqli'],
            'postgresql': ['postgresql', 'postgres', 'pg_'],
            'mssql': ['sqlsrv', 'mssql', 'sql server'],
            'oracle': ['oracle', 'ora-', 'oracle.jdbc'],
            'sqlite': ['sqlite', 'sqlite3']
        }
        
        for dbms, indicators in dbms_indicators.items():
            for indicator in indicators:
                if indicator in response_text.lower():
                    features['dbms_indicators'] += 1
        
        # Ratio de caracteres especiales
        special_chars = set("'\"\\;%_*/+-=<>()&|")
        total_chars = len(response_text)
        if total_chars > 0:
            special_count = sum(1 for c in response_text if c in special_chars)
            features['special_chars_ratio'] = special_count / total_chars
        
        # Entropía (medida de aleatoriedad)
        if total_chars > 0:
            char_counts = Counter(response_text)
            entropy = 0
            for count in char_counts.values():
                probability = count / total_chars
                entropy -= probability * math.log2(probability)
            features['entropy'] = entropy
        
        # Patrones específicos de SQLi
        features['has_union'] = 1 if 'union select' in response_text.lower() else 0
        features['has_order_by'] = 1 if 'order by' in response_text.lower() else 0
        features['has_comment'] = 1 if '--' in response_text or '/*' in response_text else 0
        
        return features


class SimpleMLClassifier:
    """Clasificador ligero basado en reglas + pesos (proto-ML)"""
    
    def __init__(self):
        self.weights = {
            'sql_errors': 10.0,
            'dbms_indicators': 8.0,
            'special_chars_ratio': 3.0,
            'has_union': 5.0,
            'has_order_by': 4.0,
            'has_comment': 2.0,
            'response_time_deviation': 3.0
        }
        self.threshold = 15.0  # Mínimo para considerar vulnerable
        self.trained = False
        self.baseline_features = None
    
    def train_baseline(self, normal_responses: List[Dict]):
        """Entrena con respuestas normales (sin payload malicioso)"""
        if not normal_responses:
            return
        
        features_list = []
        for resp in normal_responses:
            features = FeatureExtractor.extract_features(
                resp.get('text', ''),
                resp.get('status_code', 200),
                resp.get('time', 0)
            )
            features_list.append(features)
        
        # Calcular baseline promediando características normales
        self.baseline_features = {}
        for key in features_list[0].keys():
            values = [f[key] for f in features_list]
            self.baseline_features[key] = sum(values) / len(values)
        
        self.trained = True
    
    def classify(self, response_text: str, status_code: int, response_time: float) -> Tuple[bool, float, str]:
        """
        Clasifica si la respuesta indica SQLi
        
        Returns:
            (is_vulnerable, confidence_score, reason)
        """
        features = FeatureExtractor.extract_features(response_text, status_code, response_time)
        
        # Calcular score
        score = 0.0
        reasons = []
        
        # SQL errors (fuerte indicador)
        if features['sql_errors'] > 0:
            score += self.weights['sql_errors'] * min(features['sql_errors'], 3)
            reasons.append(f"SQL errors detected ({features['sql_errors']})")
        
        # DBMS indicators
        if features['dbms_indicators'] > 0:
            score += self.weights['dbms_indicators'] * min(features['dbms_indicators'], 2)
            reasons.append(f"DBMS fingerprints found")
        
        # Patrones específicos
        if features['has_union']:
            score += self.weights['has_union']
            reasons.append("UNION pattern detected")
        
        if features['has_order_by']:
            score += self.weights['has_order_by']
            reasons.append("ORDER BY pattern detected")
        
        # Desviación de baseline si está entrenado
        if self.trained and self.baseline_features:
            length_deviation = abs(features['length'] - self.baseline_features['length'])
            if length_deviation > 1000:
                score += self.weights['response_time_deviation']
                reasons.append(f"Response length anomaly ({length_deviation} bytes)")
        
        # Determinar vulnerabilidad
        is_vuln = score >= self.threshold
        confidence = min(100, (score / self.threshold) * 100) if is_vuln else max(0, 100 - (score / self.threshold) * 100)
        
        reason_str = ", ".join(reasons) if reasons else "No SQL indicators found"
        
        return is_vuln, confidence, reason_str


class MLDetector:
    """Detector principal con ML"""
    
    def __init__(self):
        self.classifier = SimpleMLClassifier()
        self.baseline_collected = []
        self.scan_history = []
    
    def collect_baseline(self, normal_request_func, num_samples=5):
        """Recolecta muestras normales para entrenamiento"""
        print("[ML] Recolectando baseline de tráfico normal...")
        
        for i in range(num_samples):
            try:
                response = normal_request_func()
                self.baseline_collected.append({
                    'text': response.text,
                    'status_code': response.status_code,
                    'time': response.elapsed.total_seconds()
                })
            except Exception as e:
                print(f"[ML] Error recolectando baseline: {e}")
        
        if self.baseline_collected:
            self.classifier.train_baseline(self.baseline_collected)
            print(f"[ML] Baseline entrenado con {len(self.baseline_collected)} muestras")
    
    def analyze_payload_response(self, payload: str, response_text: str, status_code: int, response_time: float) -> Dict:
        """Analiza una respuesta de payload específico"""
        is_vuln, confidence, reason = self.classifier.classify(response_text, status_code, response_time)
        
        analysis = {
            'payload': payload,
            'vulnerable': is_vuln,
            'confidence': confidence,
            'reason': reason,
            'status_code': status_code,
            'response_time': response_time
        }
        
        self.scan_history.append(analysis)
        return analysis
    
    def get_top_vulnerable_payloads(self, limit=5) -> List[Dict]:
        """Retorna los payloads más prometedores"""
        vulnerable = [a for a in self.scan_history if a['vulnerable']]
        vulnerable.sort(key=lambda x: x['confidence'], reverse=True)
        return vulnerable[:limit]
    
    def get_scan_report(self) -> Dict:
        """Genera reporte completo del escaneo"""
        total = len(self.scan_history)
        vulnerable = sum(1 for a in self.scan_history if a['vulnerable'])
        
        return {
            'total_payloads_tested': total,
            'vulnerable_detected': vulnerable,
            'vulnerability_rate': (vulnerable / total * 100) if total > 0 else 0,
            'average_confidence': sum(a['confidence'] for a in self.scan_history) / total if total > 0 else 0,
            'top_payloads': self.get_top_vulnerable_payloads()
        }
