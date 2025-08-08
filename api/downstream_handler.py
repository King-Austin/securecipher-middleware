import requests
import time
from django.conf import settings

def get_routing_table():
    return getattr(settings, 'ROUTING_TABLE', {})

def send_downstream_request(method, url, data=None, headers=None, timeout=30, max_retries=3):
    headers = headers or {
        'Content-Type': 'application/json',
        'User-Agent': 'SecureCipher-Middleware/1.0',
        'X-Forwarded-By': 'SecureCipher'
    }
    try:
        print(f"DEBUG: {method} {url}")
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
        print(f"DEBUG: Downstream request error: {e}")
        return {'error': str(e)}, 503

def get_bank_public_key():
    routing_table = get_routing_table()
    url = routing_table.get('public_key', 'http://localhost:8001/public-key')
    result, status = send_downstream_request("GET", url)
    if status != 200:
        raise ValueError(f"Failed to fetch public key from {url}: {status} {result}")
    key_pem = result.get('public_key')
    if not key_pem:
        raise ValueError("Banking API public key not found in response")
    return key_pem

def get_target_url(target):
    routing_table = get_routing_table()
    url = routing_table.get(target)
    if not url:
        raise ValueError(f"Unknown target: {target}")
    return url