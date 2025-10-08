import hmac
import hashlib
import base64
import json
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from .base_fuzzer import BaseFuzzer

class HMACFuzzer(BaseFuzzer):
    """
    Fuzzer for testing HMAC-SHA256 signature vulnerabilities in ACP
    """
    
    def __init__(self, secret_key: str = "test-secret-key"):
        super().__init__()
        self.secret_key = secret_key
        self.finding_type = "HMAC_VULNERABILITY"
        
    def generate_test_cases(self, base_request: Dict) -> List[Dict]:
        """
        Generate test cases for HMAC signature vulnerabilities
        
        Args:
            base_request: Base ACP request with valid signature
            
        Returns:
            List of test cases with modified signatures
        """
        test_cases = []
        
        # Extract original signature and components
        original_sig = base_request.get('headers', {}).get('Authorization', '')
        timestamp = base_request.get('headers', {}).get('X-Timestamp', '')
        
        # 1. Valid signature (control case)
        test_cases.append(base_request)
        
        # 2. Signature manipulation tests
        test_cases.extend(self._generate_signature_manipulation_cases(base_request))
        
        # 3. Timestamp manipulation tests  
        test_cases.extend(self._generate_timestamp_manipulation_cases(base_request))
        
        # 4. Canonicalization attack tests
        test_cases.extend(self._generate_canonicalization_attack_cases(base_request))
        
        # 5. Crypto vulnerability tests
        test_cases.extend(self._generate_crypto_vulnerability_cases(base_request))
        
        return test_cases
    
    def _generate_signature_manipulation_cases(self, base_request: Dict) -> List[Dict]:
        """Generate signature manipulation test cases"""
        cases = []
        original_auth = base_request.get('headers', {}).get('Authorization', '')
        
        # Various signature manipulations
        manipulations = [
            ('empty_signature', ''),
            ('null_signature', 'null'),
            ('short_signature', 'abc123'),
            ('long_signature', 'a' * 1000),
            ('special_chars', '!@#$%^&*()'),
            ('unicode_chars', 'signature_🐛_test'),
            ('base64_encoded', base64.b64encode(b'fake_signature').decode()),
            ('different_algorithm', 'SHA1:fake_signature'),
            ('no_prefix', original_auth.replace('HMAC ', '') if 'HMAC' in original_auth else original_auth),
            ('wrong_prefix', 'Bearer ' + original_auth),
            ('multiple_prefixes', 'HMAC HMAC ' + original_auth),
        ]
        
        for name, manipulated_sig in manipulations:
            modified = self._deep_copy_request(base_request)
            modified['headers']['Authorization'] = manipulated_sig
            modified['description'] = f'Signature manipulation: {name}'
            cases.append(modified)
            
        return cases
    
    def _generate_timestamp_manipulation_cases(self, base_request: Dict) -> List[Dict]:
        """Generate timestamp manipulation test cases"""
        cases = []
        original_timestamp = base_request.get('headers', {}).get('X-Timestamp', '')
        
        if not original_timestamp:
            return cases
            
        # Various timestamp manipulations
        timestamp_manipulations = [
            ('future_timestamp', self._get_future_timestamp()),
            ('past_timestamp', self._get_past_timestamp()),
            ('far_future', '3024-01-01T00:00:00Z'),
            ('ancient_past', '2020-01-01T00:00:00Z'),
            ('invalid_format', 'not-a-timestamp'),
            ('empty_timestamp', ''),
            ('null_timestamp', 'null'),
            ('unix_timestamp', str(int(time.time()))),
            ('with_timezone', '2024-01-01T00:00:00+08:00'),
            ('with_milliseconds', '2024-01-01T00:00:00.
      123Z'),
        ]
        
        for name, manipulated_ts in timestamp_manipulations:
            modified = self._deep_copy_request(base_request)
            modified['headers']['X-Timestamp'] = manipulated_ts
            
            # Recalculate signature with new timestamp if we have the secret
            if self.secret_key:
                try:
                    new_sig = self._calculate_signature(modified, self.secret_key)
                    modified['headers']['Authorization'] = new_sig
                except:
                    pass  # Keep invalid signature for testing
                    
            modified['description'] = f'Timestamp manipulation: {name}'
            cases.append(modified)
            
        return cases
    
    def _generate_canonicalization_attack_cases(self, base_request: Dict) -> List[Dict]:
        """Generate JSON canonicalization attack test cases"""
        cases = []
        
        # Different JSON serializations that should produce same canonical form
        json_variations = []
        
        original_body = base_request.get('body', {})
        if isinstance(original_body, dict):
            # Space variations
            json_variations.append(('minified', json.dumps(original_body, separators=(',', ':'))))
            json_variations.append(('spaced', json.dumps(original_body, indent=2)))
            json_variations.append(('extra_spaces', json.dumps(original_body, indent=4)))
            
            # Key order variations (shouldn't matter for proper canonicalization)
            if len(original_body) > 1:
                reversed_keys = {k: original_body[k] for k in reversed(list(original_body.keys()))}
                json_variations.append(('reversed_keys', json.dumps(reversed_keys)))
                
            # Unicode variations
            json_variations.append(('unicode_escape', json.dumps(original_body, ensure_ascii=True)))
            json_variations.append(('unicode_raw', json.dumps(original_body, ensure_ascii=False)))
            
        for name, json_body in json_variations:
            modified = self._deep_copy_request(base_request)
            modified['body'] = json_body
            
            # Recalculate signature with canonical JSON
            if self.secret_key:
                try:
                    # Test if server properly canonicalizes before verifying
                    new_sig = self._calculate_signature(modified, self.secret_key)
                    modified['headers']['Authorization'] = new_sig
                except:
                    pass
                    
            modified['description'] = f'JSON canonicalization: {name}'
            cases.append(modified)
            
        return cases
    
    def _generate_crypto_vulnerability_cases(self, base_request: Dict) -> List[Dict]:
        """Generate cryptographic vulnerability test cases"""
        cases = []
        
        # Length extension attack simulation
        modified = self._deep_copy_request(base_request)
        original_sig = base_request.get('headers', {}).get('Authorization', '')
        
        # Try to extend the signature
        if original_sig and len(original_sig) > 10:
            extended_sig = original_sig + "_extended_data"
            modified['headers']['Authorization'] = extended_sig
            modified['description'] = 'Signature length extension attempt'
            cases.append(modified)
        
        # Hash collision attempts (simplified)
        collision_tests = [
            ('zero_hash', '0' * 64),
            ('all_ff_hash', 'f' * 64),
            ('short_hash', 'abc123'),
            ('null_bytes', 'signature\0with\0null'),
        ]
        
        for name, fake_sig in collision_tests:
            modified = self._deep_copy_request(base_request)
            modified['headers']['Authorization'] = fake_sig
            modified['description'] = f'Hash collision test: {name}'
            cases.append(modified)
            
        return cases
      def execute_tests(self, target_url: str, test_cases: List[Dict]) -> List[Dict]:
        """
        Execute HMAC signature tests and analyze responses
        
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
                
                # Analyze response for vulnerabilities
                analysis = self._analyze_hmac_response(
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
                self.logger.error(f"HMAC test case {i} failed: {e}")
                continue
                
            # Rate limiting
            time.sleep(self.config.get('request_delay', 0.1))
            
        return results
    
    def _analyze_hmac_response(self, ref_response: Dict, test_response: Dict, 
                             test_case: Dict) -> Dict:
        """
        Analyze responses for HMAC-specific vulnerabilities
        
        Args:
            ref_response: Reference (valid) response
            test_response: Test case response
            test_case: Test case details
            
        Returns:
            Vulnerability analysis
        """
        vulnerabilities = []
        severity = 0
        
        # Check for signature bypass
        if (test_response.get('status_code') == 200 and 
            'invalid signature' not in str(test_response).lower() and
            'unauthorized' not in str(test_response).lower()):
            
            # Successful request with invalid signature = critical vulnerability
            vulnerabilities.append("SIGNATURE_BYPASS")
            severity = max(severity, 5)  # Critical
            
        # Check for timing differences (potential timing attack vulnerability)
        timing_diff = self._detect_timing_difference(ref_response, test_response)
        if timing_diff > 0.5:  # 500ms difference
            vulnerabilities.append("TIMING_ATTACK_VULNERABILITY")
            severity = max(severity, 4)  # High
            
        # Check for information leakage in error messages
        error_info = self._check_error_information_leakage(test_response)
        if error_info:
            vulnerabilities.append(f"INFORMATION_LEAKAGE: {error_info}")
            severity = max(severity, 3)  # Medium
            
        # Check for canonicalization issues
        if self._detect_canonicalization_issue(test_case, test_response):
            vulnerabilities.append("CANONICALIZATION_VULNERABILITY")
            severity = max(severity, 4)  # High
            
        return {
            'is_vulnerability': len(vulnerabilities) > 0,
            'severity': severity,
            'evidence': vulnerabilities,
            'vulnerability_type': vulnerabilities[0] if vulnerabilities else 'NONE'
        }
    
    def _calculate_signature(self, request: Dict, secret_key: str) -> str:
        """
        Calculate HMAC-SHA256 signature for ACP request
        
        Args:
      request: Request data
            secret_key: Secret key for signing
            
        Returns:
            Base64-encoded signature
        """
        # ACP canonicalization: method + path + sorted query params + canonical JSON body + timestamp
        components = []
        
        # HTTP method
        components.append(request.get('method', 'GET').upper())
        
        # Path
        url_parts = urlparse(request.get('url', ''))
        components.append(url_parts.path)
        
        # Sorted query parameters
        query_params = parse_qs(url_parts.query)
        sorted_query = '&'.join(f"{k}={','.join(sorted(v))}" for k, v in sorted(query_params.items()))
        components.append(sorted_query)
        
        # Canonical JSON body
        body = request.get('body', {})
        if isinstance(body, dict):
            canonical_json = json.dumps(body, sort_keys=True, separators=(',', ':'))
        else:
            canonical_json = str(body)
        components.append(canonical_json)
        
        # Timestamp
        timestamp = request.get('headers', {}).get('X-Timestamp', '')
        components.append(timestamp)
        
        # Create signing string
        signing_string = '\n'.join(components)
        
        # Calculate HMAC-SHA256
        signature = hmac.new(
            secret_key.encode('utf-8'),
            signing_string.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Base64 encode
        return f"HMAC {base64.b64encode(signature).decode('utf-8')}"
    
    def _get_future_timestamp(self, minutes: int = 5) -> str:
        """Get RFC 3339 timestamp for future time"""
        future = time.time() + (minutes * 60)
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(future))
    
    def _get_past_timestamp(self, minutes: int = 5) -> str:
        """Get RFC 3339 timestamp for past time"""
        past = time.time() - (minutes * 60)
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(past))
    
    def _detect_timing_difference(self, ref_response: Dict, test_response: Dict) -> float:
        """Detect significant timing differences in responses"""
        ref_time = ref_response.get('elapsed_time', 0)
        test_time = test_response.get('elapsed_time', 0)
        return abs(test_time - ref_time)
    
    def _check_error_information_leakage(self, response: Dict) -> str:
        """Check if error responses leak sensitive information"""
        error_indicators = [
            'stack trace', 'file path', 'database error', 'sql exception',
            'secret key', 'api key', 'password', 'signature algorithm'
        ]
        
        response_text = str(response).lower()
        for indicator in error_indicators:
            if indicator in response_text:
                return indicator
                
        return ""
    
    def _detect_canonicalization_issue(self, test_case: Dict, response: Dict) -> bool:
        """Detect potential JSON canonicalization issues"""
        if 'canonicalization' in test_case.get('description', '').lower():
            # If canonicalization test passes with invalid signature, that's a vulnerability
            if response.get('status_code') == 200:
                return True
        return False
