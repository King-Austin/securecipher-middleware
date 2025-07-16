"""
Downstream Service Handler for SecureCipher Middleware

This module handles communication with downstream services (banking APIs, etc.)
after cryptographic validation is complete.
"""

import requests
import time
from typing import Dict, Any, Optional, Tuple
from django.conf import settings


class DownstreamServiceHandler:
    """
    Handles communication with downstream services after cryptographic validation.
    Manages routing, request formatting, error handling, and response processing.
    """
    
    def __init__(self):
        self.routing_table = getattr(settings, 'ROUTING_TABLE', {})
        self.default_timeout = 30
        self.max_retries = 3
        
    def get_route_info(self, target_key: str) -> Dict[str, Any]:
        """
        Get routing information for a target key.
        
        Args:
            target_key: The routing key (e.g., 'auth_register', 'transactions_transfer')
            
        Returns:
            Dict containing route information (url, method, etc.)
            
        Raises:
            ValueError: If target key is invalid or not found
        """
        if not target_key or target_key not in self.routing_table:
            raise ValueError(f"Invalid or missing target: {target_key}")
            
        return self.routing_table[target_key]
    
    def format_downstream_url(self, base_url: str, url_params: Optional[Dict[str, Any]] = None) -> str:
        """
        Format the downstream URL with path parameters.
        
        Args:
            base_url: The base URL template
            url_params: Optional parameters to format into the URL
            
        Returns:
            Formatted URL string
        """
        if url_params:
            try:
                return base_url.format(**url_params)
            except KeyError as e:
                raise ValueError(f"Missing required URL parameter: {e}")
        return base_url
    
    def prepare_request_headers(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Prepare headers for downstream request.
        
        Args:
            custom_headers: Optional custom headers to include
            
        Returns:
            Dictionary of headers
        """
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'SecureCipher-Middleware/1.0',
            'X-Forwarded-By': 'SecureCipher'
        }
        
        if custom_headers:
            headers.update(custom_headers)
            
        return headers
    
    def make_downstream_request(
        self, 
        method: str, 
        url: str, 
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> requests.Response:
        """
        Make HTTP request to downstream service with retry logic.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            url: Destination URL
            data: Request payload
            headers: Request headers
            timeout: Request timeout in seconds
            
        Returns:
            requests.Response object
            
        Raises:
            ValueError: If request fails after all retries
        """
        request_timeout = timeout or self.default_timeout
        request_headers = self.prepare_request_headers(headers)
        
        print(f"DEBUG: Making {method} request to {url}")
        print(f"DEBUG: Request data: {data}")
        
        last_exception = None
        
        for attempt in range(self.max_retries):
            try:
                response = requests.request(
                    method=method.upper(),
                    url=url,
                    json=data if data else None,
                    headers=request_headers,
                    timeout=request_timeout
                )
                
                print(f"DEBUG: Downstream response status: {response.status_code}")
                return response
                
            except requests.exceptions.Timeout as e:
                last_exception = e
                print(f"DEBUG: Request timeout on attempt {attempt + 1}/{self.max_retries}")
                
            except requests.exceptions.ConnectionError as e:
                last_exception = e
                print(f"DEBUG: Connection error on attempt {attempt + 1}/{self.max_retries}")
                
            except requests.exceptions.RequestException as e:
                last_exception = e
                print(f"DEBUG: Request exception on attempt {attempt + 1}/{self.max_retries}: {e}")
                
            # Wait before retry (exponential backoff)
            if attempt < self.max_retries - 1:
                wait_time = 2 ** attempt
                print(f"DEBUG: Waiting {wait_time} seconds before retry...")
                time.sleep(wait_time)
        
        # All retries failed
        raise ValueError(f"Failed to communicate with downstream service after {self.max_retries} attempts: {last_exception}")
    
    def process_downstream_response(self, response: requests.Response) -> Tuple[Dict[str, Any], int]:
        """
        Process response from downstream service.
        
        Args:
            response: requests.Response object
            
        Returns:
            Tuple of (response_data, status_code)
        """
        try:
            response_data = response.json()
        except ValueError:
            # Handle non-JSON responses
            response_data = {
                'error': 'Invalid JSON response from downstream service',
                'raw_response': response.text[:500]  # Truncate for safety
            }
        
        return response_data, response.status_code
    
    def forward_transaction(
        self, 
        target_key: str, 
        transaction_data: Dict[str, Any],
        url_params: Optional[Dict[str, Any]] = None,
        custom_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[Dict[str, Any], int]:
        """
        Forward validated transaction to downstream service.
        
        Args:
            target_key: The routing key
            transaction_data: Validated transaction data
            url_params: Optional URL parameters
            custom_headers: Optional custom headers
            
        Returns:
            Tuple of (response_data, status_code)
            
        Raises:
            ValueError: If routing or request fails
        """
        # Get route information
        route_info = self.get_route_info(target_key)
        
        # Extract route details
        base_url = route_info['url']
        http_method = route_info['method']
        
        # Format URL with parameters
        formatted_url = self.format_downstream_url(base_url, url_params)
        
        print(f"DEBUG: Forwarding to {http_method} {formatted_url}")
        
        # Make the request
        response = self.make_downstream_request(
            method=http_method,
            url=formatted_url,
            data=transaction_data,
            headers=custom_headers
        )
        
        # Process and return response
        return self.process_downstream_response(response)


class DownstreamServiceManager:
    """
    Manager class for handling multiple downstream service operations.
    Provides high-level interface for common operations.
    """
    
    def __init__(self):
        self.handler = DownstreamServiceHandler()
    
    def route_transaction(
        self, 
        transaction_components: Dict[str, Any]
    ) -> Tuple[Dict[str, Any], int]:
        """
        Route a complete transaction to the appropriate downstream service.
        
        Args:
            transaction_components: Complete transaction components including:
                - target: routing key
                - transaction_data: payload
                - url_params: optional URL parameters
                
        Returns:
            Tuple of (response_data, status_code)
        """
        target_key = transaction_components.get('target')
        transaction_data = transaction_components.get('transaction_data', {})
        url_params = transaction_components.get('url_params')
        
        return self.handler.forward_transaction(
            target_key=target_key,
            transaction_data=transaction_data,
            url_params=url_params
        )
    
    def test_connection(self, target_key: str) -> Dict[str, Any]:
        """
        Test connection to a downstream service with minimal payload.
        
        Args:
            target_key: The routing key to test
            
        Returns:
            Test result dictionary
        """
        try:
            # Get route info
            route_info = self.handler.get_route_info(target_key)
            
            # Simple test based on method
            if route_info['method'].upper() == 'GET':
                # For GET endpoints, just try to connect
                response = self.handler.make_downstream_request(
                    method='GET',
                    url=route_info['url'].split('{')[0],  # Remove parameter placeholders
                    timeout=5
                )
            else:
                # For POST/PUT endpoints, try with empty payload
                response = self.handler.make_downstream_request(
                    method=route_info['method'],
                    url=route_info['url'],
                    data={},
                    timeout=5
                )
            
            return {
                'status': 'success',
                'target': target_key,
                'response_code': response.status_code,
                'response_time': 'fast',  # Could add actual timing
                'url': route_info['url']
            }
            
        except Exception as e:
            return {
                'status': 'failed',
                'target': target_key,
                'error': str(e),
                'url': route_info.get('url', 'unknown') if 'route_info' in locals() else 'unknown'
            }
