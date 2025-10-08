import pytest
import json
from src.modules.fuzzing.hmac_fuzzer import HMACFuzzer

class TestHMACFuzzer:
    
    def setup_method(self):
        self.fuzzer = HMACFuzzer(secret_key="test-secret-123")
        self.base_request = {
            'method': 'POST',
            'url': 'https://api.example.com/orders',
            'headers': {
                'Authorization': 'HMAC abc123',
                'X-Timestamp': '2024-01-01T00:00:00Z',
                'Content-Type': 'application/json'
            },
            'body': {
                'amount': 1000,
                'currency': 'USD',
                'items': [{'product_id': 'test_1', 'quantity': 1}]
            }
        }
    
    def test_generate_test_cases(self):
        """Test generation of HMAC test cases"""
        cases = self.fuzzer.generate_test_cases(self.base_request)
        
        assert len(cases) > 0
        assert cases[0] == self.base_request  # First case should be original
        
        # Should contain various manipulation types
        case_descriptions = [case.get('description', '') for case in cases]
        assert any('signature manipulation' in desc for desc in case_descriptions)
        assert any('timestamp manipulation' in desc for desc in case_descriptions)
        assert any('canonicalization' in desc for desc in case_descriptions)
    
    def test_signature_calculation(self):
        """Test HMAC signature calculation"""
        request = {
            'method': 'POST',
            'url': 'https://api.example.com/test?param=value',
            'headers': {
                'X-Timestamp': '2024-01-01T00:00:00Z'
            },
            'body': {'test': 'data'}
        }
        
        signature = self.fuzzer._calculate_signature(request, 'test-key')
        
        assert signature.startswith('HMAC ')
        assert len(signature) > 10
    
    def test_timestamp_manipulation_cases(self):
        """Test timestamp manipulation case generation"""
        cases = self.fuzzer._generate_timestamp_manipulation_cases(self.base_request)
        
        assert len(cases) > 0
        
        # Check timestamp variations
        timestamps = [case['headers']['X-Timestamp'] for case in cases]
        assert any('2020' in ts for ts in timestamps)  # Past timestamp
        assert any('3024' in ts for ts in timestamps)  # Future timestamp
    
    def test_canonicalization_cases(self):
        """Test JSON canonicalization case generation"""
        cases = self.fuzzer._generate_canonicalization_attack_cases(self.base_request)
        
        assert len(cases) > 0
        
        # Should contain different JSON serializations
        descriptions = [case['description'] for case in cases]
        assert any('minified' in desc for desc in descriptions)
        assert any('spaced' in desc for desc in descriptions)
    
    def test_response_analysis(self):
        """Test HMAC response analysis"""
        ref_response = {'status_code': 200, 'elapsed_time': 0.1}
        test_response = {'status_code': 200, 'elapsed_time': 0.1}
        test_case = {'description': 'signature manipulation: empty_signature'}
        
        analysis = self.fuzzer._analyze_hmac_response(
            ref_response, test_response, test_case
        )
        
        # Should detect signature bypass
        assert analysis['is_vulnerability'] == True
        assert analysis['severity'] == 5
        assert 'SIGNATURE_BYPASS' in analysis['evidence']
