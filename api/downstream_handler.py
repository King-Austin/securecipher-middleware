import requests
import time
from typing import Dict, Any, Optional, Tuple
from django.conf import settings

class DownstreamServiceHandler:
    def __init__(self):
        self.routing_table = getattr(settings, 'ROUTING_TABLE', {})
        self.default_timeout = 30
        self.max_retries = 3

    def get_route_info(self, target_key: str) -> Dict[str, Any]:
        if not target_key or not isinstance(target_key, str):
            raise ValueError(f"Invalid target: {target_key}")
        if target_key in self.routing_table:
            return self.routing_table[target_key]
        raise ValueError(f"Invalid or missing target: '{target_key}'. Available: {list(self.routing_table.keys())[:5]}")

    def format_url(self, base_url: str, url_params: Optional[Dict[str, Any]] = None) -> str:
        if url_params:
            try:
                return base_url.format(**url_params)
            except KeyError as e:
                raise ValueError(f"Missing URL parameter: {e}")
        return base_url

    def make_request(self, method: str, url: str, data=None, headers=None, timeout=None) -> requests.Response:
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
                return resp
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.RequestException) as e:
                last_exception = e
                print(f"DEBUG: Downstream request error: {e}")
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
        raise ValueError(f"Downstream service failed after {self.max_retries} attempts: {last_exception}")

    def process_response(self, response: requests.Response) -> Tuple[Dict[str, Any], int]:
        try:
            return response.json(), response.status_code
        except ValueError:
            return {'error': 'Invalid JSON from downstream', 'raw_response': response.text[:500]}, response.status_code

    def forward_transaction(self, target_key: str, transaction_data: Dict[str, Any], url_params=None, headers=None) -> Tuple[Dict[str, Any], int]:
        route = self.get_route_info(target_key)
        url = self.format_url(route['url'], url_params)
        resp = self.make_request(route['method'], url, data=transaction_data, headers=headers)
        return self.process_response(resp)

class DownstreamServiceManager:
    def __init__(self):
        self.handler = DownstreamServiceHandler()

    def route_transaction(self, transaction_components: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        return self.handler.forward_transaction(
            target_key=transaction_components.get('target'),
            transaction_data=transaction_components.get('transaction_data', {}),
            url_params=transaction_components.get('url_params')
        )