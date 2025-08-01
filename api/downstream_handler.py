import requests
import time
from django.conf import settings

class DownstreamServiceHandler:
    def __init__(self):
        self.routing_table = getattr(settings, 'ROUTING_TABLE', {})
        self.default_timeout = 30
        self.max_retries = 3

    def send_request(self, method, url, data=None, headers=None, timeout=None):
        headers = headers or {
            'Content-Type': 'application/json',
            'User-Agent': 'SecureCipher-Middleware/1.0',
            'X-Forwarded-By': 'SecureCipher'
        }
        timeout = timeout or self.default_timeout
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                print(f"DEBUG: {method} {url} | Attempt {attempt+1}")
                resp = requests.request(
                    method=method.upper(),
                    url=url,
                    json=data,
                    headers=headers,
                    timeout=timeout
                )
                print(f"DEBUG: Downstream status: {resp.status_code}")

                
                try:
                    return resp.json(), resp.status_code
                except ValueError:
                    return {'error': 'Invalid JSON from downstream', 'raw_response': resp.text[:500]}, resp.status_code
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
                last_exception = e
                print(f"DEBUG: Downstream request error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
        raise ValueError(f"Downstream service failed after {self.max_retries} attempts: {last_exception}")


    def get_bank_public_key(self):
        """Fetch the banking API public key (PEM format)."""
        url = self.routing_table.get('public_key', 'http://localhost:8001/public-key')
        result, status = self.send_request("GET", url)
        if status != 200:
            raise ValueError(f"Failed to fetch public key from {url}: {status} {result}")
        key_pem = result.get('public_key')
        if not key_pem:
            raise ValueError("Banking API public key not found in response")
        return key_pem  # Return PEM string directly

class DownstreamServiceManager:
    def __init__(self):
        self.handler = DownstreamServiceHandler()

    def route_transaction(self, payload, url, method="POST", headers=None):
        return self.handler.send_request(method, url, payload, headers=headers)