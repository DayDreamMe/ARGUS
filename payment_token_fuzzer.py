import json
import time
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from .base_fuzzer import BaseFuzzer

class PaymentTokenFuzzer(BaseFuzzer):
    """
    Security auditor for ACP payment token implementation
    Tests delegation, usage, and validation of payment tokens
    """
    
    def __init__(self):
        super().__init__()
        self.finding_type = "PAYMENT_TOKEN_VULNERABILITY"
        
    def generate_test_cases(self, base_request: Dict) -> List[Dict]:
        """
        Generate test cases for payment token vulnerabilities
        
        Args:
            base_request: Base ACP request with payment token
            
        Returns:
            List of test cases with manipulated payment tokens
        """
        test_cases = []
        
        # 1. Valid payment token (control case)
        test_cases.append(base_request)
        
        # 2. Token delegation tests
        test_cases.extend(self._generate_token_delegation_tests(base_request))
        
        # 3. Token usage tests  
        test_cases.extend(self._generate_token_usage_tests(base_request))
        
        # 4. Token validation tests
        test_cases.extend(self._generate_token_validation_tests(base_request))
        
        # 5. Business logic bypass tests
        test_cases.extend(self._generate_business_logic_tests(base_request))
        
        return test_cases
    
    def _generate_token_delegation_tests(self, base_request: Dict) -> List[Dict]:
        """Generate tests for token delegation endpoint"""
        cases = []
        
        # Base delegation request
        delegation_base = {
            'method': 'POST',
            'url': f"{base_request.get('url', '').split('/api/')[0]}/agentic_commerce/delegate_payment",
            'headers': base_request.get('headers', {}).copy(),
            'body': {
                'max_amount': 1000,
                'currency': 'USD',
                'expires_in': 300,  # 5 minutes
                'purpose': 'test_purchase'
            }
        }
        
        # Amount manipulation tests
        amount_tests = [
            ('negative_amount', -100),
            ('zero_amount', 0),
            ('very_large_amount', 1e10),
            ('decimal_amount', 99.99),
            ('string_amount', "1000"),
            ('null_amount', None),
            ('exponential_amount', 1e6),
        ]
        
        for name, amount in amount_tests:
            modified = self._deep_copy_request(delegation_base)
            modified['body']['max_amount'] = amount
            modified['description'] = f'Delegation amount: {name}'
            modified['delegation_test'] = True
            cases.append(modified)
        
        # Currency manipulation tests
        currency_tests = [
            ('empty_currency', ''),
            ('invalid_currency', 'XYZ'),
            ('lowercase_currency', 'usd'),
            ('special_chars', 'US$'),
            ('long_currency', 'USDUSDUSD'),
            ('null_currency', None),
            ('number_currency', 840),  # USD numeric code
        ]
        
        for name, currency in currency_tests:
            modified = self._deep_copy_request(delegation_base)
            modified['body']['currency'] = currency
            modified['description'] = f'Delegation currency: {name}'
            modified['delegation_test'] = True
            cases.append(modified)
        
        # Expiration manipulation tests
        expiration_tests = [
            ('immediate_expiration', 0),
            ('very_short', 1),
            ('very_long', 86400 * 365),  # 1 year
            ('negative_expiration', -100),
            ('string_expiration', "300"),
            ('null_expiration', None),
            ('float_expiration', 300.5),
        ]
        
        for name, expires_in in expiration_tests:
            modified = self._deep_copy_request(delegation_base)
          modified['body']['expires_in'] = expires_in
            modified['description'] = f'Delegation expiration: {name}'
            modified['delegation_test'] = True
            cases.append(modified)
            
        return cases
    
    def _generate_token_usage_tests(self, base_request: Dict) -> List[Dict]:
        """Generate tests for payment token usage"""
        cases = []
        
        # Extract original payment token if present
        original_token = self._extract_payment_token(base_request)
        
        if not original_token:
            return cases
            
        # Token manipulation tests
        token_manipulations = [
            ('empty_token', ''),
            ('null_token', 'null'),
            ('invalid_format', 'not-a-valid-token'),
            ('short_token', 'abc'),
            ('long_token', 'a' * 1000),
            ('special_chars', 'token_!@#$%_123'),
            ('sql_injection', "token' OR '1'='1"),
            ('xss_attempt', 'token<script>alert(1)</script>'),
            ('path_traversal', '../../../etc/passwd'),
            ('unicode_token', 'token_🐛_test'),
            ('different_case', original_token.upper() if original_token else ''),
            ('trimmed_token', original_token.strip() if original_token else ''),
            ('duplicate_token', original_token + original_token if original_token else ''),
        ]
        
        for name, manipulated_token in token_manipulations:
            modified = self._deep_copy_request(base_request)
            self._inject_payment_token(modified, manipulated_token)
            modified['description'] = f'Token manipulation: {name}'
            modified['token_usage_test'] = True
            cases.append(modified)
        
        # Reuse and replay tests
        reuse_tests = [
            ('multiple_uses', 'Reuse token across multiple requests'),
            ('after_expiration', 'Use token after theoretical expiration'),
            ('different_amounts', 'Use token with different amounts'),
            ('different_currencies', 'Use token with different currencies'),
            ('different_endpoints', 'Use token on different API endpoints'),
        ]
        
        for name, description in reuse_tests:
            modified = self._deep_copy_request(base_request)
            modified['description'] = f'Token reuse: {name}'
            modified['token_reuse_test'] = True
            cases.append(modified)
            
        return cases
    
    def _generate_token_validation_tests(self, base_request: Dict) -> List[Dict]:
        """Generate tests for token validation logic"""
        cases = []
        
        # Amount validation tests
        amount_validation_tests = [
            ('amount_exceeds_limit', 1500),  # Above token limit
            ('amount_zero', 0),
            ('amount_negative', -100),
            ('amount_string', "500"),
            ('amount_float', 500.75),
            ('amount_null', None),
            ('amount_scientific', 1e3),
        ]
        
        for name, amount in amount_validation_tests:
            modified = self._deep_copy_request(base_request)
            if 'body' in modified and isinstance(modified['body'], dict):
                modified['body']['amount'] = amount
            modified['description'] = f'Amount validation: {name}'
            modified['validation_test'] = True
            cases.append(modified)
        
        # Currency validation tests
        currency_validation_tests = [
            ('currency_mismatch', 'EUR'),  # Different from token
            ('currency_lowercase', 'usd'),
            ('currency_empty', ''),
            ('currency_invalid', 'XXX'),
            ('currency_null', None),
            ('currency_number', 840),
        ]
        
        for name, currency in currency_validation_tests:
            modified = self._deep_copy_request(base_request)
            if 'body' in modified and isinstance(modified['body'], dict):
                modified['body']['currency'] = currency
              modified['description'] = f'Currency validation: {name}'
            modified['validation_test'] = True
            cases.append(modified)
        
        # Metadata manipulation tests
        metadata_tests = [
            ('extra_fields', {'extra_field': 'malicious_data'}),
            ('modified_fields', {'purpose': 'different_purpose'}),
            ('null_metadata', None),
            ('array_metadata', ['item1', 'item2']),
            ('deep_nesting', {'nested': {'deeply': {'secret': 'data'}}}),
        ]
        
        for name, metadata in metadata_tests:
            modified = self._deep_copy_request(base_request)
            if 'body' in modified and isinstance(modified['body'], dict):
                if name == 'extra_fields':
                    modified['body'].update(metadata)
                elif name == 'modified_fields':
                    modified['body']['purpose'] = metadata['purpose']
                else:
                    modified['body']['metadata'] = metadata
            modified['description'] = f'Metadata manipulation: {name}'
            modified['validation_test'] = True
            cases.append(modified)
            
        return cases
    
    def _generate_business_logic_tests(self, base_request: Dict) -> List[Dict]:
        """Generate tests for business logic bypasses"""
        cases = []
        
        # Parallel usage tests
        parallel_tests = [
            ('parallel_same_token', 'Use same token in parallel requests'),
            ('parallel_different_tokens', 'Use different tokens in parallel'),
            ('race_condition', 'Race condition in token validation'),
        ]
        
        for name, description in parallel_tests:
            modified = self._deep_copy_request(base_request)
            modified['description'] = f'Business logic: {name}'
            modified['parallel_test'] = True
            cases.append(modified)
        
        # Token lifecycle tests
        lifecycle_tests = [
            ('revoked_token', 'Use theoretically revoked token'),
            ('regenerated_token', 'Use old token after regeneration'),
            ('cross_user_token', 'Use token from different user context'),
            ('cross_merchant_token', 'Use token at different merchant'),
        ]
        
        for name, description in lifecycle_tests:
            modified = self._deep_copy_request(base_request)
            modified['description'] = f'Token lifecycle: {name}'
            modified['lifecycle_test'] = True
            cases.append(modified)
        
        # Payment flow bypass tests
        bypass_tests = [
            ('direct_charge', 'Attempt direct charge without token delegation'),
            ('modify_amount_after_auth', 'Change amount after user authorization'),
            ('reuse_auth_session', 'Reuse authorization session'),
        ]
        
        for name, description in bypass_tests:
            modified = self._deep_copy_request(base_request)
            modified['description'] = f'Flow bypass: {name}'
            modified['bypass_test'] = True
            cases.append(modified)
            
        return cases
    
    def _extract_payment_token(self, request: Dict) -> Optional[str]:
        """Extract payment token from request"""
        # Look in different common locations
        body = request.get('body', {})
        if isinstance(body, dict):
            # Common field names for payment tokens
            token_fields = ['payment_token', 'token', 'delegated_token', 'shared_token']
            for field in token_fields:
                if field in body:
                    return body[field]
        
        # Check headers
        headers = request.get('headers', {})
        if 'X-Payment-Token' in headers:
            return headers['X-Payment-Token']
            
        return None
    
    def _inject_payment_token(self, request: Dict, token: str) -> None:
        """Inject payment token into request"""
        body = request.get('body', {})
        if isinstance(body, dict):
          # Try to find existing token field
            token_fields = ['payment_token', 'token', 'delegated_token', 'shared_token']
            for field in token_fields:
                if field in body:
                    body[field] = token
                    return
            
            # If no existing field, add to common field
            body['payment_token'] = token
    
    def execute_tests(self, target_url: str, test_cases: List[Dict]) -> List[Dict]:
        """
        Execute payment token security tests
        
        Args:
            target_url: Target ACP endpoint
            test_cases: Generated test cases
            
        Returns:
            List of security findings
        """
        results = []
        reference_response = None
        captured_tokens = {}  # Store tokens for reuse tests
        
        for i, test_case in enumerate(test_cases):
            try:
                # Special handling for delegation tests
                if test_case.get('delegation_test'):
                    result = self._execute_delegation_test(test_case)
                    if result and 'token' in result:
                        captured_tokens[test_case['description']] = result['token']
                    continue
                
                # Send regular request
                response = self._send_request(target_url, test_case)
                
                # First valid case is reference
                if i == 0 and response.get('status_code') == 200:
                    reference_response = response
                    continue
                
                # Analyze response for token vulnerabilities
                analysis = self._analyze_token_response(
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
                self.logger.error(f"Payment token test case {i} failed: {e}")
                continue
                
            # Rate limiting
            time.sleep(self.config.get('request_delay', 0.1))
        
        # Execute token reuse tests
        reuse_results = self._execute_token_reuse_tests(captured_tokens, target_url)
        results.extend(reuse_results)
            
        return results
    
    def _execute_delegation_test(self, test_case: Dict) -> Optional[Dict]:
        """
        Execute payment token delegation test
        
        Args:
            test_case: Delegation test case
            
        Returns:
            Delegation result with token if successful
        """
        try:
            response = self._send_request(test_case['url'], test_case)
            
            if response.get('status_code') == 200:
                # Parse response to extract token
                response_body = response.get('body', '{}')
                if isinstance(response_body, str):
                    try:
                        response_data = json.loads(response_body)
                        if 'token' in response_data:
                            return {
                                'token': response_data['token'],
                                'response': response
                            }
                    except json.JSONDecodeError:
                        pass
            
            return None
            
        except Exception as e:
            self.logger.error(f"Delegation test failed: {e}")
            return None
          def _execute_token_reuse_tests(self, captured_tokens: Dict, target_url: str) -> List[Dict]:
        """Execute token reuse and replay tests"""
        results = []
        
        for test_name, token in captured_tokens.items():
            try:
                # Test 1: Reuse token multiple times
                reuse_responses = []
                for i in range(3):  # Try to reuse 3 times
                    reuse_request = {
                        'method': 'POST',
                        'url': target_url,
                        'headers': {'Content-Type': 'application/json'},
                        'body': {
                            'payment_token': token,
                            'amount': 100,
                            'currency': 'USD'
                        }
                    }
                    
                    response = self._send_request(target_url, reuse_request)
                    reuse_responses.append(response)
                    time.sleep(0.1)  # Small delay between requests
                
                # Analyze reuse results
                reuse_analysis = self._analyze_token_reuse(reuse_responses, test_name)
                if reuse_analysis['is_vulnerability']:
                    results.append({
                        'test_case': f'Token reuse: {test_name}',
                        'severity': reuse_analysis['severity'],
                        'evidence': reuse_analysis['evidence'],
                        'vulnerability_type': 'TOKEN_REUSE',
                        'test_response': reuse_responses
                    })
                    
            except Exception as e:
                self.logger.error(f"Token reuse test failed for {test_name}: {e}")
                continue
                
        return results
    
    def _analyze_token_response(self, ref_response: Dict, test_response: Dict, 
                              test_case: Dict) -> Dict:
        """
        Analyze responses for payment token vulnerabilities
        
        Args:
            ref_response: Reference (valid) response
            test_response: Test case response
            test_case: Test case details
            
        Returns:
            Vulnerability analysis
        """
        vulnerabilities = []
        severity = 0
        
        # Check for token validation bypass
        if (test_response.get('status_code') == 200 and 
            test_case.get('token_usage_test') and
            'invalid token' not in str(test_response).lower() and
            'unauthorized' not in str(test_response).lower()):
            
            vulnerabilities.append("TOKEN_VALIDATION_BYPASS")
            severity = max(severity, 5)  # Critical
            
        # Check for amount validation bypass
        if (test_response.get('status_code') == 200 and 
            test_case.get('validation_test') and
            'amount' in str(test_case).lower() and
            'exceed' not in str(test_response).lower() and
            'invalid amount' not in str(test_response).lower()):
            
            vulnerabilities.append("AMOUNT_VALIDATION_BYPASS")
            severity = max(severity, 4)  # High
            
        # Check for business logic bypass
        if (test_response.get('status_code') == 200 and 
            test_case.get('bypass_test')):
            
            vulnerabilities.append("BUSINESS_LOGIC_BYPASS")
            severity = max(severity, 4)  # High
            
        # Check for information leakage
        error_info = self._check_token_error_leakage(test_response)
        if error_info:
            vulnerabilities.append(f"TOKEN_ERROR_LEAKAGE: {error_info}")
            severity = max(severity, 3)  # Medium
            
        return {
            'is_vulnerability': len(vulnerabilities) > 0,
            'severity': severity,
            'evidence': vulnerabilities,
            'vulnerability_type': vulnerabilities[0] if vulnerabilities else 'NONE'
        }
    
    def _analyze_token_reuse(self, responses: List[Dict], test_name: str) -> Dict:
      """Analyze token reuse attempt results"""
        successful_charges = 0
        for response in responses:
            if response.get('status_code') == 200:
                successful_charges += 1
        
        if successful_charges > 1:
            return {
                'is_vulnerability': True,
                'severity': 5,  # Critical
                'evidence': [f'Token reused {successful_charges} times successfully']
            }
        else:
            return {
                'is_vulnerability': False,
                'severity': 0,
                'evidence': []
            }
    
    def _check_token_error_leakage(self, response: Dict) -> str:
        """Check if token errors leak sensitive information"""
        sensitive_indicators = [
            'token secret', 'signing key', 'hmac key', 'database error',
            'internal error', 'stack trace', 'token algorithm', 'expiration time'
        ]
        
        response_text = str(response).lower()
        for indicator in sensitive_indicators:
            if indicator in response_text:
                return indicator
                
        return ""
