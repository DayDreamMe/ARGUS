import json
import re
from typing import Dict, List, Any, Optional
from .base_fuzzer import BaseFuzzer

class JSONCanonicalizationFuzzer(BaseFuzzer):
    """
    Fuzzer for testing JSON canonicalization vulnerabilities in ACP
    ACP requires strict JSON canonicalization for HMAC signature verification
    """
    
    def __init__(self):
        super().__init__()
        self.finding_type = "CANONICALIZATION_VULNERABILITY"
        
    def generate_test_cases(self, base_request: Dict) -> List[Dict]:
        """
        Generate test cases for JSON canonicalization vulnerabilities
        
        Args:
            base_request: Base ACP request with valid JSON body
            
        Returns:
            List of test cases with non-canonical JSON
        """
        test_cases = []
        
        # Extract original JSON body
        original_body = base_request.get('body', {})
        
        # 1. Valid canonical JSON (control case)
        test_cases.append(base_request)
        
        # 2. Whitespace variations
        test_cases.extend(self._generate_whitespace_variations(base_request))
        
        # 3. Key ordering variations
        test_cases.extend(self._generate_key_ordering_variations(base_request))
        
        # 4. Number representation variations
        test_cases.extend(self._generate_number_variations(base_request))
        
        # 5. String encoding variations
        test_cases.extend(self._generate_string_encoding_variations(base_request))
        
        # 6. Unicode and special character variations
        test_cases.extend(self._generate_unicode_variations(base_request))
        
        # 7. Structural variations
        test_cases.extend(self._generate_structural_variations(base_request))
        
        # 8. Boundary value tests
        test_cases.extend(self._generate_boundary_value_tests(base_request))
        
        return test_cases
    
    def _generate_whitespace_variations(self, base_request: Dict) -> List[Dict]:
        """Generate whitespace variations in JSON"""
        cases = []
        original_body = base_request.get('body', {})
        
        if not isinstance(original_body, dict):
            return cases
            
        whitespace_variations = [
            ('minified', json.dumps(original_body, separators=(',', ':'))),
            ('pretty_2_spaces', json.dumps(original_body, indent=2)),
            ('pretty_4_spaces', json.dumps(original_body, indent=4)),
            ('pretty_tabs', json.dumps(original_body, indent='\t')),
            ('no_spaces', json.dumps(original_body, separators=(',', ':')).replace(' ', '')),
            ('extra_spaces', json.dumps(original_body, indent=2).replace(' ', '  ')),
            ('trailing_spaces', json.dumps(original_body) + '   '),
            ('leading_spaces', '   ' + json.dumps(original_body)),
            ('mixed_whitespace', json.dumps(original_body).replace(' ', '\t')),
            ('newlines_in_strings', self._inject_newlines_in_strings(original_body)),
        ]
        
        for name, json_str in whitespace_variations:
            modified = self._deep_copy_request(base_request)
            modified['body'] = json_str
            modified['description'] = f'Whitespace variation: {name}'
            modified['canonicalization_test'] = True
            cases.append(modified)
            
        return cases
    
    def _generate_key_ordering_variations(self, base_request: Dict) -> List[Dict]:
        """Generate key ordering variations in JSON objects"""
        cases = []
        original_body = base_request.get('body', {})
        
        if not isinstance(original_body, dict) or len(original_body) < 2:
            return cases
            
        # Different key orders
        key_orders = [
            ('sorted_keys', dict(sorted(original_body.items()))),
            ('reverse_sorted', dict(sorted(original_body.items(), reverse=True))),
      ('random_order_1', self._shuffle_dict(original_body)),
            ('random_order_2', self._shuffle_dict(original_body)),
        ]
        
        for name, reordered_dict in key_orders:
            modified = self._deep_copy_request(base_request)
            modified['body'] = reordered_dict
            modified['description'] = f'Key ordering: {name}'
            modified['canonicalization_test'] = True
            cases.append(modified)
            
        return cases
    
    def _generate_number_variations(self, base_request: Dict) -> List[Dict]:
        """Generate number representation variations"""
        cases = []
        original_body = base_request.get('body', {})
        
        def transform_numbers(obj):
            """Recursively transform number representations"""
            if isinstance(obj, dict):
                return {k: transform_numbers(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [transform_numbers(v) for v in obj]
            elif isinstance(obj, (int, float)):
                # Return multiple representations for the same number
                return obj
            else:
                return obj
        
        number_variations = [
            ('leading_zeros', self._transform_number_representation(original_body, 'leading_zeros')),
            ('scientific_notation', self._transform_number_representation(original_body, 'scientific')),
            ('decimal_precision', self._transform_number_representation(original_body, 'precision')),
            ('negative_zero', self._transform_number_representation(original_body, 'negative_zero')),
        ]
        
        for name, transformed_body in number_variations:
            if transformed_body != original_body:
                modified = self._deep_copy_request(base_request)
                modified['body'] = transformed_body
                modified['description'] = f'Number representation: {name}'
                modified['canonicalization_test'] = True
                cases.append(modified)
                
        return cases
    
    def _generate_string_encoding_variations(self, base_request: Dict) -> List[Dict]:
        """Generate string encoding variations"""
        cases = []
        original_body = base_request.get('body', {})
        
        string_variations = [
            ('unicode_escaped', json.dumps(original_body, ensure_ascii=True)),
            ('unicode_raw', json.dumps(original_body, ensure_ascii=False)),
            ('control_chars', self._inject_control_chars(original_body)),
            ('escape_sequences', self._inject_escape_sequences(original_body)),
        ]
        
        for name, json_str in string_variations:
            modified = self._deep_copy_request(base_request)
            modified['body'] = json_str
            modified['description'] = f'String encoding: {name}'
            modified['canonicalization_test'] = True
            cases.append(modified)
            
        return cases
    
    def _generate_unicode_variations(self, base_request: Dict) -> List[Dict]:
        """Generate Unicode and special character tests"""
        cases = []
        original_body = base_request.get('body', {})
        
        unicode_tests = [
            ('emoji', {'text': 'Hello 🚀 World', 'amount': 100}),
            ('special_chars', {'text': 'Line\nBreak\tTab', 'amount': 100}),
            ('unicode_normalization', {'text': 'café', 'amount': 100}),  # vs 'cafe\u0301'
            ('right_to_left', {'text': 'Hello \u202eWorld', 'amount': 100}),
            ('zero_width', {'text': 'Hello\u200bWorld', 'amount': 100}),
            ('sql_injection_chars', {'query': "test'; DROP TABLE--", 'amount': 100}),
        ]
        
        for name, test_body in unicode_tests:
            modified = self._deep_copy_request(base_request)
            # Merge with original body to preserve structure
            merged_body = original_body.copy() if isinstance(original_body, dict) else {}
            merged_body.update(test_body)
          modified['body'] = merged_body
            modified['description'] = f'Unicode/special chars: {name}'
            modified['canonicalization_test'] = True
            cases.append(modified)
            
        return cases
    
    def _generate_structural_variations(self, base_request: Dict) -> List[Dict]:
        """Generate JSON structural variations"""
        cases = []
        original_body = base_request.get('body', {})
        
        structural_variations = [
            ('empty_objects', self._inject_empty_objects(original_body)),
            ('null_values', self._replace_with_null(original_body)),
            ('duplicate_keys', self._create_duplicate_keys(original_body)),
            ('deep_nesting', self._create_deep_nesting(original_body)),
        ]
        
        for name, transformed_body in structural_variations:
            if transformed_body != original_body:
                modified = self._deep_copy_request(base_request)
                modified['body'] = transformed_body
                modified['description'] = f'Structural variation: {name}'
                modified['canonicalization_test'] = True
                cases.append(modified)
                
        return cases
    
    def _generate_boundary_value_tests(self, base_request: Dict) -> List[Dict]:
        """Generate boundary value tests"""
        cases = []
        original_body = base_request.get('body', {})
        
        boundary_tests = [
            ('very_large_numbers', {'amount': 1e308, 'precision': 1e-308}),
            ('very_long_strings', {'description': 'A' * 10000, 'amount': 100}),
            ('empty_strings', {'text': '', 'amount': 100}),
            ('max_depth', self._create_max_depth_object()),
        ]
        
        for name, test_body in boundary_tests:
            modified = self._deep_copy_request(base_request)
            merged_body = original_body.copy() if isinstance(original_body, dict) else {}
            merged_body.update(test_body)
            modified['body'] = merged_body
            modified['description'] = f'Boundary test: {name}'
            modified['canonicalization_test'] = True
            cases.append(modified)
            
        return cases
    
    # Helper methods for JSON transformations
    
    def _inject_newlines_in_strings(self, obj: Any) -> str:
        """Inject newlines and tabs into string values"""
        if isinstance(obj, dict):
            transformed = {}
            for k, v in obj.items():
                if isinstance(v, str):
                    transformed[k] = v + '\n\t'
                else:
                    transformed[k] = self._inject_newlines_in_strings(v)
            return json.dumps(transformed)
        return json.dumps(obj)
    
    def _shuffle_dict(self, d: Dict) -> Dict:
        """Shuffle dictionary keys (different from sorted)"""
        import random
        keys = list(d.keys())
        random.shuffle(keys)
        return {k: d[k] for k in keys}
    
    def _transform_number_representation(self, obj: Any, style: str) -> Any:
        """Transform number representations"""
        if isinstance(obj, dict):
            return {k: self._transform_number_representation(v, style) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._transform_number_representation(v, style) for v in obj]
        elif isinstance(obj, int):
            if style == 'leading_zeros' and obj < 1000:
                return f"{obj:04d}"  # Convert to string with leading zeros
            elif style == 'scientific' and obj > 1000:
                return f"{obj:.2e}"  # Scientific notation
        elif isinstance(obj, float):
            if style == 'precision':
                return round(obj, 10)  # Different precision
            elif style == 'negative_zero':
                return -0.0  # Negative zero
        return obj
    
    def _inject_control_chars(self, obj: Any) -> str:
        """Inject control characters into strings"""
        if isinstance(obj, dict):
            transformed = {}
          for k, v in obj.items():
                if isinstance(v, str):
                    transformed[k] = v + '\x00\x01\x02'  NULL, SOH, STX
                else:
                    transformed[k] = self._inject_control_chars(v)
            return json.dumps(transformed, ensure_ascii=False)
        return json.dumps(obj, ensure_ascii=False)
    
    def _inject_escape_sequences(self, obj: Any) -> str:
        """Inject escape sequences"""
        if isinstance(obj, dict):
            transformed = {}
            for k, v in obj.items():
                if isinstance(v, str):
                    transformed[k] = v.replace('"', '\\"').replace('\n', '\\n')
                else:
                    transformed[k] = self._inject_escape_sequences(v)
            return json.dumps(transformed)
        return json.dumps(obj)
    
    def _inject_empty_objects(self, obj: Any) -> Any:
        """Inject empty objects and arrays"""
        if isinstance(obj, dict):
            transformed = obj.copy()
            transformed['empty_obj'] = {}
            transformed['empty_arr'] = []
            return transformed
        return obj
    
    def _replace_with_null(self, obj: Any) -> Any:
        """Replace some values with null"""
        if isinstance(obj, dict) and len(obj) > 1:
            transformed = obj.copy()
            keys = list(transformed.keys())
            if keys:
                transformed[keys[0]] = None  # Replace first value with null
            return transformed
        return obj
    
    def _create_duplicate_keys(self, obj: Any) -> str:
        """Create JSON with duplicate keys (should be invalid)"""
        if isinstance(obj, dict):
            json_str = json.dumps(obj)
            # Inject duplicate key
            if '"amount":' in json_str:
                json_str = json_str.replace('"amount":', '"amount":100, "amount":200,')
            return json_str
        return json.dumps(obj)
    
    def _create_deep_nesting(self, obj: Any) -> Any:
        """Create deeply nested JSON structures"""
        if isinstance(obj, dict):
            deep_obj = {"level_1": {"level_2": {"level_3": {"level_4": {"level_5": "deep_value"}}}}}
            if isinstance(obj, dict):
                obj = obj.copy()
                obj['deeply_nested'] = deep_obj
            return obj
        return obj
    
    def _create_max_depth_object(self, depth: int = 50) -> Dict:
        """Create maximally deep JSON object"""
        obj = {"value": "bottom"}
        for i in range(depth):
            obj = {"level": depth - i, "child": obj}
        return obj
    
    def execute_tests(self, target_url: str, test_cases: List[Dict]) -> List[Dict]:
        """
        Execute JSON canonicalization tests
        
        Args:
            target_url: Target ACP endpoint
            test_cases: Generated test cases
            
        Returns:
            List of security findings
        """
        results = []
        reference_response = None
        
        for i, test_case in enumerate(test_cases):
            try:
                # Send request
                response = self._send_request(target_url, test_case)
                
                # First valid case is reference
                if i == 0 and response.get('status_code') == 200:
                    reference_response = response
                    continue
                
                # Analyze response for canonicalization vulnerabilities
                analysis = self._analyze_canonicalization_response(
                    reference_response, 
                    response, 
                    test_case
                )
                
                if analysis['is_vulnerability']:
                    results.append({
                        'test_case': test_case['description'],
                        'severity': analysis['severity'],
                        'evidence': analysis['evidence'],
                        'vulnerability_type': analysis['vulnerability_type'],
                        'reference_response': reference_response,
                      'test_response': response
                    })
                    
            except Exception as e:
                self.logger.error(f"Canonicalization test case {i} failed: {e}")
                continue
                
            # Rate limiting
            time.sleep(self.config.get('request_delay', 0.1))
            
        return results
    
    def _analyze_canonicalization_response(self, ref_response: Dict, test_response: Dict, 
                                         test_case: Dict) -> Dict:
        """
        Analyze responses for canonicalization vulnerabilities
        
        Args:
            ref_response: Reference (valid) response
            test_response: Test case response
            test_case: Test case details
            
        Returns:
            Vulnerability analysis
        """
        vulnerabilities = []
        severity = 0
        
        # Check if non-canonical JSON was accepted
        if (test_response.get('status_code') == 200 and 
            test_case.get('canonicalization_test') and
            'invalid json' not in str(test_response).lower() and
            'parse error' not in str(test_response).lower()):
            
            # Non-canonical JSON accepted = canonicalization vulnerability
            vulnerabilities.append("CANONICALIZATION_BYPASS")
            severity = max(severity, 4)  # High severity
            
        # Check for different behavior between canonical and non-canonical
        if (ref_response and test_response and
            ref_response.get('status_code') != test_response.get('status_code') and
            test_case.get('canonicalization_test')):
            
            vulnerabilities.append("INCONSISTENT_CANONICALIZATION")
            severity = max(severity, 3)  # Medium severity
            
        # Check for error information leakage
        error_info = self._check_canonicalization_error_leakage(test_response)
        if error_info:
            vulnerabilities.append(f"ERROR_LEAKAGE: {error_info}")
            severity = max(severity, 2)  # Low severity
            
        return {
            'is_vulnerability': len(vulnerabilities) > 0,
            'severity': severity,
            'evidence': vulnerabilities,
            'vulnerability_type': vulnerabilities[0] if vulnerabilities else 'NONE'
        }
    
    def _check_canonicalization_error_leakage(self, response: Dict) -> str:
        """Check if canonicalization errors leak sensitive information"""
        error_indicators = [
            'parser stack', 'token', 'line', 'column', 'position',
            'json.parse', 'serialization', 'deserialization'
        ]
        
        response_text = str(response).lower()
        for indicator in error_indicators:
            if indicator in response_text:
                return indicator
                
        return ""
