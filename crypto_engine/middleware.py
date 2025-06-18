"""
SecureCipher Middleware
Handles cryptographic validation for incoming requests
"""

import json
import time
import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.conf import settings

from .models import UserCryptoKey, CryptoAuditLog
from .utils import CryptoValidator

logger = logging.getLogger('crypto_engine')

class SecureCipherMiddleware(MiddlewareMixin):
    """
    Middleware to handle SecureCipher cryptographic validation
    Processes requests with X-Secure-Cipher header
    """
    
    def process_request(self, request):
        # Skip crypto validation for non-secure requests
        if not request.headers.get('X-Secure-Cipher'):
            return None
        
        start_time = time.time()
        request_id = request.headers.get('X-Request-ID', 'unknown')
        
        logger.info(f"🔐 Processing secure request: {request.method} {request.path} (ID: {request_id})")
        
        try:
            # Extract crypto headers
            signature = request.headers.get('X-Signature')
            timestamp = request.headers.get('X-Timestamp')
            
            if not all([signature, request_id, timestamp]):
                missing = []
                if not signature: missing.append('X-Signature')
                if not request_id: missing.append('X-Request-ID')
                if not timestamp: missing.append('X-Timestamp')
                
                return self.crypto_error_response(
                    f'Missing cryptographic headers: {", ".join(missing)}',
                    'MISSING_CRYPTO_HEADERS',
                    400,
                    request,
                    missing_headers=missing
                )
            
            # Parse request body
            try:
                if request.body:
                    request_data = json.loads(request.body)
                else:
                    request_data = {}
            except json.JSONDecodeError as e:
                return self.crypto_error_response(
                    f'Invalid JSON in request body: {str(e)}',
                    'INVALID_JSON',
                    400,
                    request,
                    json_error=str(e)
                )
            
            # Get and validate fingerprint
            fingerprint = request_data.get('public_key_fingerprint')
            if not fingerprint:
                return self.crypto_error_response(
                    'Missing public_key_fingerprint in request body',
                    'MISSING_FINGERPRINT',
                    400,
                    request
                )
            
            # Validate timestamp (prevent replay attacks)
            max_age = getattr(settings, 'SECURE_CIPHER_CONFIG', {}).get('SIGNATURE_TIMEOUT', 300)
            if not CryptoValidator.validate_timestamp(timestamp, max_age_seconds=max_age):
                self.log_crypto_operation(
                    None, request, 'verify', False, 
                    f'Request timestamp expired (max age: {max_age}s)', request_id, 
                    fingerprint, start_time
                )
                
                return self.crypto_error_response(
                    'Request timestamp expired or invalid',
                    'TIMESTAMP_EXPIRED',
                    401,
                    request,
                    fingerprint,
                    max_age_seconds=max_age
                )
            
            # Get user's crypto key
            try:
                crypto_key = UserCryptoKey.objects.get(
                    fingerprint=fingerprint,
                    is_active=True
                )
            except UserCryptoKey.DoesNotExist:
                self.log_crypto_operation(
                    None, request, 'verify', False, 
                    'Public key not found or inactive', request_id, 
                    fingerprint, start_time
                )
                
                return self.crypto_error_response(
                    'Invalid or unregistered public key',
                    'INVALID_KEY',
                    401,
                    request,
                    fingerprint
                )
            
            # Prepare payload for signature verification
            payload = {
                'endpoint': request.path,
                'method': request.method,
                'data': request_data.get('data'),
                'timestamp': timestamp,
                'request_id': request_id
            }
            
            # Verify cryptographic signature
            is_valid = CryptoValidator.verify_ecdsa_signature(
                payload=payload,
                signature=signature,
                public_key_jwk=crypto_key.public_key_jwk
            )
            
            if not is_valid:
                self.log_crypto_operation(
                    crypto_key, request, 'verify', False, 
                    'Invalid cryptographic signature', request_id, 
                    fingerprint, start_time
                )
                
                return self.crypto_error_response(
                    'Invalid cryptographic signature',
                    'INVALID_SIGNATURE',
                    401,
                    request,
                    fingerprint
                )
            
            # Handle encrypted data if present
            decrypted_data = None
            if 'encrypted_data' in request_data:
                try:
                    encrypted_info = request_data['encrypted_data']
                    
                    # Validate encrypted data structure
                    required_fields = ['encrypted', 'key', 'iv']
                    if not all(field in encrypted_info for field in required_fields):
                        missing = [f for f in required_fields if f not in encrypted_info]
                        raise ValueError(f"Missing encrypted data fields: {missing}")
                    
                    decrypted_data = CryptoValidator.decrypt_aes_data(
                        encrypted_info['encrypted'],
                        encrypted_info['key'],
                        encrypted_info['iv']
                    )
                    
                    logger.info(f"🔓 Successfully decrypted data for request {request_id}")
                    
                except Exception as e:
                    logger.error(f"❌ Decryption failed for request {request_id}: {str(e)}")
                    
                    self.log_crypto_operation(
                        crypto_key, request, 'decrypt', False, 
                        f'Decryption failed: {str(e)}', request_id, 
                        fingerprint, start_time
                    )
                    
                    return self.crypto_error_response(
                        'Failed to decrypt request data',
                        'DECRYPTION_FAILED',
                        400,
                        request,
                        fingerprint,
                        decryption_error=str(e)
                    )
            
            # Check if sensitive endpoint requires encryption
            if CryptoValidator.is_sensitive_endpoint(request.path):
                require_encryption = getattr(settings, 'SECURE_CIPHER_CONFIG', {}).get('REQUIRE_ENCRYPTION_FOR_SENSITIVE', True)
                
                if require_encryption and not decrypted_data and request_data.get('data'):
                    logger.warning(f"⚠️ Sensitive endpoint {request.path} accessed without encryption")
                    
                    return self.crypto_error_response(
                        'This sensitive endpoint requires encrypted data',
                        'ENCRYPTION_REQUIRED',
                        400,
                        request,
                        fingerprint
                    )
            
            # Store validated data in request object
            request.secure_data = decrypted_data or request_data.get('data', {})
            request.crypto_key = crypto_key
            request.crypto_verified = True
            request.crypto_fingerprint = fingerprint
            request.crypto_request_id = request_id
            request.crypto_timestamp = timestamp
            request.crypto_encrypted = bool(decrypted_data)
            
            # Update key usage
            crypto_key.last_used = timezone.now()
            crypto_key.save(update_fields=['last_used'])
            
            # Log successful verification
            operation = 'decrypt' if decrypted_data else 'verify'
            self.log_crypto_operation(
                crypto_key, request, operation, True, 
                '', request_id, fingerprint, start_time
            )
            
            processing_time_ms = int((time.time() - start_time) * 1000)
            logger.info(f"✅ Crypto verification successful for request {request_id} ({processing_time_ms}ms)")
            
            return None  # Continue processing
            
        except Exception as e:
            logger.error(f"❌ Crypto middleware error for request {request_id}: {str(e)}")
            
            self.log_crypto_operation(
                None, request, 'verify', False, 
                f'Middleware error: {str(e)}', request_id, 
                request_data.get('public_key_fingerprint', 'unknown') if 'request_data' in locals() else 'unknown', 
                start_time
            )
            
            return self.crypto_error_response(
                'Cryptographic validation failed',
                'CRYPTO_ERROR',
                500,
                request,
                request_data.get('public_key_fingerprint', 'unknown') if 'request_data' in locals() else 'unknown',
                internal_error=str(e)
            )
    
    def crypto_error_response(self, message, code, status_code, request, fingerprint='unknown', **extra_data):
        """Generate standardized crypto error response"""
        response_data = {
            'error': message,
            'code': code,
            'timestamp': timezone.now().isoformat(),
            'path': request.path,
            'method': request.method,
            'request_id': request.headers.get('X-Request-ID', 'unknown'),
            'fingerprint': fingerprint
        }
        
        # Add extra debugging data in development
        if getattr(settings, 'DEBUG', False):
            response_data.update(extra_data)
        
        return JsonResponse(response_data, status=status_code)
    
    def log_crypto_operation(self, crypto_key, request, operation, success, error_msg='', request_id='', fingerprint='unknown', start_time=None):
        """Log cryptographic operations for audit trail"""
        try:
            processing_time_ms = None
            if start_time:
                processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Sanitize request data for audit
            request_audit_data = {
                'method': request.method,
                'path': request.path,
                'has_crypto_header': bool(request.headers.get('X-Secure-Cipher')),
                'has_signature': bool(request.headers.get('X-Signature')),
                'has_timestamp': bool(request.headers.get('X-Timestamp')),
                'content_length': len(request.body) if request.body else 0
            }
            
            # Add encrypted data info if available
            try:
                if request.body:
                    body_data = json.loads(request.body)
                    request_audit_data['has_encrypted_data'] = 'encrypted_data' in body_data
            except:
                pass
            
            CryptoAuditLog.objects.create(
                user=crypto_key.user if crypto_key else None,
                fingerprint=fingerprint,
                operation=operation,
                endpoint=request.path,
                request_id=request_id or request.headers.get('X-Request-ID', ''),
                ip_address=self.get_client_ip(request),
                user_agent=request.headers.get('User-Agent', ''),
                success=success,
                error_message=error_msg,
                request_data=request_audit_data,
                response_code=200 if success else 401,
                processing_time_ms=processing_time_ms
            )
            
        except Exception as e:
            logger.error(f"Failed to log crypto operation: {str(e)}")
    
    def get_client_ip(self, request):
        """Extract client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')
