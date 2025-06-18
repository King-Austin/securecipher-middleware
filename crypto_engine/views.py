"""
SecureCipher Crypto Engine Views
API endpoints for cryptographic operations and key management
"""

import time
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction
from django.conf import settings

from .models import UserCryptoKey, CryptoAuditLog
from .utils import CryptoValidator
import logging

logger = logging.getLogger('crypto_engine')
User = get_user_model()

class RegisterPublicKeyView(APIView):
    """
    Register user's public key for cryptographic operations
    POST /api/auth/register-key/
    """
    permission_classes = [AllowAny]  # Allow anonymous key registration
    
    def post(self, request):
        start_time = time.time()
        
        try:
            logger.info(f"🔐 Processing public key registration from {self.get_client_ip(request)}")
            data = request.data
            
            # Extract public key data
            public_key_jwk = data.get('public_key')
            algorithm = data.get('algorithm', 'ECDSA')
            curve = data.get('curve', 'P-384')
            device_info = data.get('device_info', {})
            
            # Validate required fields
            if not public_key_jwk:
                return Response({
                    'error': 'Public key is required',
                    'code': 'MISSING_PUBLIC_KEY'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate key format
            required_jwk_fields = ['kty', 'crv', 'x', 'y']
            if not all(field in public_key_jwk for field in required_jwk_fields):
                return Response({
                    'error': 'Invalid public key format. Required fields: kty, crv, x, y',
                    'code': 'INVALID_KEY_FORMAT',
                    'missing_fields': [f for f in required_jwk_fields if f not in public_key_jwk]
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate algorithm and curve
            if public_key_jwk.get('kty') != 'EC':
                return Response({
                    'error': f"Invalid key type: {public_key_jwk.get('kty')}. Expected: EC",
                    'code': 'INVALID_KEY_TYPE'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if public_key_jwk.get('crv') != 'P-384':
                return Response({
                    'error': f"Invalid curve: {public_key_jwk.get('crv')}. Expected: P-384",
                    'code': 'INVALID_CURVE'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Generate fingerprint
            try:
                fingerprint = CryptoValidator.generate_fingerprint(public_key_jwk)
            except ValueError as e:
                return Response({
                    'error': f'Invalid key format: {str(e)}',
                    'code': 'FINGERPRINT_GENERATION_FAILED'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Validate the key by attempting to convert it
            try:
                CryptoValidator.jwk_to_ec_public_key(public_key_jwk)
            except ValueError as e:
                return Response({
                    'error': f'Invalid public key: {str(e)}',
                    'code': 'INVALID_PUBLIC_KEY'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Store device information
            device_data = {
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'ip_address': self.get_client_ip(request),
                'registered_at': timezone.now().isoformat(),
                'algorithm': algorithm,
                'curve': curve,
                **device_info
            }
            
            # Store or update crypto key
            with transaction.atomic():
                crypto_key, created = UserCryptoKey.objects.update_or_create(
                    fingerprint=fingerprint,
                    defaults={
                        'user': request.user if request.user.is_authenticated else None,
                        'public_key_jwk': public_key_jwk,
                        'algorithm': algorithm,
                        'curve': curve,
                        'is_active': True,
                        'device_info': device_data,
                        'last_used': timezone.now()
                    }
                )
                
                # Calculate processing time
                processing_time_ms = int((time.time() - start_time) * 1000)
                
                # Log the registration
                CryptoAuditLog.objects.create(
                    user=crypto_key.user,
                    fingerprint=fingerprint,
                    operation='register',
                    endpoint=request.path,
                    request_id=data.get('request_id', f'reg_{int(timezone.now().timestamp())}'),
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=True,
                    request_data=CryptoValidator.sanitize_audit_data({
                        'algorithm': algorithm, 
                        'curve': curve,
                        'key_type': public_key_jwk.get('kty'),
                        'has_device_info': bool(device_info)
                    }),
                    response_code=201 if created else 200,
                    processing_time_ms=processing_time_ms
                )
            
            action = "registered" if created else "updated"
            logger.info(f"{'✅ New' if created else '🔄 Updated'} crypto key {action}: {fingerprint} ({processing_time_ms}ms)")
            
            return Response({
                'success': True,
                'fingerprint': fingerprint,
                'key_id': crypto_key.id,
                'algorithm': algorithm,
                'curve': curve,
                'message': f'Public key {action} successfully',
                'created': created,
                'server_time': timezone.now().isoformat(),
                'processing_time_ms': processing_time_ms
            }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)
            
        except Exception as e:
            processing_time_ms = int((time.time() - start_time) * 1000)
            logger.error(f"❌ Public key registration failed: {str(e)} ({processing_time_ms}ms)")
            
            # Log failed registration
            try:
                CryptoAuditLog.objects.create(
                    fingerprint='unknown',
                    operation='register',
                    endpoint=request.path,
                    request_id=data.get('request_id', 'unknown') if 'data' in locals() else 'unknown',
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=False,
                    error_message=str(e),
                    response_code=500,
                    processing_time_ms=processing_time_ms
                )
            except:
                pass  # Don't fail on audit log errors
            
            return Response({
                'error': 'Failed to register public key',
                'details': str(e),
                'code': 'REGISTRATION_FAILED'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_client_ip(self, request):
        """Extract client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class VerifySignatureView(APIView):
    """
    Verify cryptographic signature for request validation
    POST /api/auth/verify-signature/
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        start_time = time.time()
        
        try:
            logger.info(f"🔍 Processing signature verification from {self.get_client_ip(request)}")
            data = request.data
            
            # Extract signature data
            signature = data.get('signature')
            payload = data.get('payload')
            fingerprint = data.get('public_key_fingerprint')
            
            # Validate required fields
            if not all([signature, payload, fingerprint]):
                return Response({
                    'error': 'Missing required fields',
                    'code': 'MISSING_FIELDS',
                    'required_fields': ['signature', 'payload', 'public_key_fingerprint'],
                    'provided_fields': [k for k in [signature, payload, fingerprint] if k]
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get user's public key
            try:
                crypto_key = UserCryptoKey.objects.get(
                    fingerprint=fingerprint,
                    is_active=True
                )
            except UserCryptoKey.DoesNotExist:
                processing_time_ms = int((time.time() - start_time) * 1000)
                
                # Log failed verification
                CryptoAuditLog.objects.create(
                    fingerprint=fingerprint,
                    operation='verify',
                    endpoint=request.path,
                    request_id=payload.get('request_id', 'unknown') if isinstance(payload, dict) else 'unknown',
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    success=False,
                    error_message='Public key not found or inactive',
                    response_code=404,
                    processing_time_ms=processing_time_ms
                )
                
                logger.warning(f"❌ Public key not found: {fingerprint} ({processing_time_ms}ms)")
                return Response({
                    'error': 'Public key not found or inactive',
                    'code': 'KEY_NOT_FOUND',
                    'fingerprint': fingerprint
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Validate timestamp if present
            timestamp = payload.get('timestamp')
            if timestamp:
                max_age = getattr(settings, 'SECURE_CIPHER_CONFIG', {}).get('SIGNATURE_TIMEOUT', 300)
                if not CryptoValidator.validate_timestamp(timestamp, max_age_seconds=max_age):
                    processing_time_ms = int((time.time() - start_time) * 1000)
                    
                    CryptoAuditLog.objects.create(
                        user=crypto_key.user,
                        fingerprint=fingerprint,
                        operation='verify',
                        endpoint=request.path,
                        request_id=payload.get('request_id', 'unknown'),
                        ip_address=self.get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        success=False,
                        error_message='Request timestamp expired or invalid',
                        response_code=401,
                        processing_time_ms=processing_time_ms
                    )
                    
                    return Response({
                        'error': 'Request timestamp is invalid or expired',
                        'code': 'TIMESTAMP_EXPIRED',
                        'max_age_seconds': max_age
                    }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Verify signature
            is_valid = CryptoValidator.verify_ecdsa_signature(
                payload=payload,
                signature=signature,
                public_key_jwk=crypto_key.public_key_jwk
            )
            
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Update last used timestamp if valid
            if is_valid:
                crypto_key.last_used = timezone.now()
                crypto_key.save(update_fields=['last_used'])
            
            # Log verification attempt
            CryptoAuditLog.objects.create(
                user=crypto_key.user,
                fingerprint=fingerprint,
                operation='verify',
                endpoint=request.path,
                request_id=payload.get('request_id', 'unknown'),
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=is_valid,
                error_message='' if is_valid else 'Invalid cryptographic signature',
                request_data=CryptoValidator.sanitize_audit_data({
                    'endpoint': payload.get('endpoint'),
                    'method': payload.get('method'),
                    'has_timestamp': bool(timestamp)
                }),
                response_code=200 if is_valid else 401,
                processing_time_ms=processing_time_ms
            )
            
            if not is_valid:
                logger.warning(f"❌ Invalid signature for {fingerprint} ({processing_time_ms}ms)")
                return Response({
                    'error': 'Invalid cryptographic signature',
                    'code': 'INVALID_SIGNATURE',
                    'fingerprint': fingerprint
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            logger.info(f"✅ Signature verification successful for {fingerprint} ({processing_time_ms}ms)")
            
            return Response({
                'valid': is_valid,
                'fingerprint': fingerprint,
                'algorithm': crypto_key.algorithm,
                'curve': crypto_key.curve,
                'verified_at': timezone.now().isoformat(),
                'key_last_used': crypto_key.last_used.isoformat(),
                'processing_time_ms': processing_time_ms
            })
            
        except Exception as e:
            processing_time_ms = int((time.time() - start_time) * 1000)
            logger.error(f"❌ Signature verification failed: {str(e)} ({processing_time_ms}ms)")
            
            return Response({
                'error': 'Signature verification failed',
                'details': str(e),
                'code': 'VERIFICATION_FAILED'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_client_ip(self, request):
        """Extract client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class CryptoStatusView(APIView):
    """
    Check cryptographic setup status and system health
    GET /api/auth/crypto-status/
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        start_time = time.time()
        
        try:
            logger.info(f"📊 Processing crypto status check from {self.get_client_ip(request)}")
            
            fingerprint = request.GET.get('fingerprint')
            user_id = request.user.id if request.user.is_authenticated else None
            
            crypto_data = {
                'crypto_enabled': False,
                'requires_setup': True,
                'key_count': 0,
                'server_time': timezone.now().isoformat(),
                'system_status': 'healthy'
            }
            
            if fingerprint:
                # Check specific key
                crypto_key = UserCryptoKey.objects.filter(
                    fingerprint=fingerprint,
                    is_active=True
                ).first()
                
                if crypto_key:
                    crypto_data.update({
                        'crypto_enabled': True,
                        'requires_setup': False,
                        'key_count': 1,
                        'fingerprint': fingerprint,
                        'short_fingerprint': crypto_key.short_fingerprint,
                        'algorithm': crypto_key.algorithm,
                        'curve': crypto_key.curve,
                        'created_at': crypto_key.created_at.isoformat(),
                        'last_used': crypto_key.last_used.isoformat(),
                        'associated_user': crypto_key.user.username if crypto_key.user else None
                    })
                    
                    # Get recent activity
                    recent_logs = CryptoAuditLog.objects.filter(
                        fingerprint=fingerprint
                    ).order_by('-timestamp')[:5]
                    
                    crypto_data['recent_activity'] = [
                        {
                            'operation': log.get_operation_display(),
                            'timestamp': log.timestamp.isoformat(),
                            'success': log.success,
                            'endpoint': log.endpoint
                        }
                        for log in recent_logs
                    ]
            
            elif user_id:
                # Check user's keys
                user_keys = UserCryptoKey.objects.filter(
                    user_id=user_id,
                    is_active=True
                )
                
                if user_keys.exists():
                    latest_key = user_keys.order_by('-last_used').first()
                    crypto_data.update({
                        'crypto_enabled': True,
                        'requires_setup': False,
                        'key_count': user_keys.count(),
                        'latest_fingerprint': latest_key.fingerprint,
                        'latest_short_fingerprint': latest_key.short_fingerprint,
                        'algorithm': latest_key.algorithm,
                        'curve': latest_key.curve,
                        'last_used': latest_key.last_used.isoformat(),
                        'keys': [
                            {
                                'fingerprint': key.fingerprint,
                                'short_fingerprint': key.short_fingerprint,
                                'created_at': key.created_at.isoformat(),
                                'last_used': key.last_used.isoformat(),
                                'device_info': key.device_info
                            }
                            for key in user_keys
                        ]
                    })
            
            # Add system statistics
            total_keys = UserCryptoKey.objects.filter(is_active=True).count()
            total_operations = CryptoAuditLog.objects.count()
            
            crypto_data['system_stats'] = {
                'total_active_keys': total_keys,
                'total_operations': total_operations,
                'server_version': '1.0.0',
                'crypto_algorithms_supported': ['ECDSA'],
                'curves_supported': ['P-384'],
                'encryption_supported': ['AES-256-GCM']
            }
            
            processing_time_ms = int((time.time() - start_time) * 1000)
            crypto_data['processing_time_ms'] = processing_time_ms
            
            logger.info(f"✅ Crypto status check completed ({processing_time_ms}ms)")
            
            return Response(crypto_data)
            
        except Exception as e:
            processing_time_ms = int((time.time() - start_time) * 1000)
            logger.error(f"❌ Crypto status check failed: {str(e)} ({processing_time_ms}ms)")
            
            return Response({
                'error': 'Status check failed',
                'details': str(e),
                'code': 'STATUS_CHECK_FAILED',
                'system_status': 'error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_client_ip(self, request):
        """Extract client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')
