"""
SecureCipher Gateway Module
Handles secure gateway for encrypted and signed communications
"""

import json
import base64
import time
import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.utils import timezone
from django.db import transaction

from crypto_engine.crypto_utils import (
    load_pem_public_key,
    derive_session_key,
    decrypt_payload,
    verify_signature,
    sign_payload,
    encrypt_payload,
    encode_binary,
    decode_binary,
    encode_signature,
    decode_signature,
    load_pem_private_key
)
from crypto_engine.models import MiddlewareKey, TransactionLog

logger = logging.getLogger('crypto_engine')

class MiddlewarePublicKeyView(APIView):
    """
    Endpoint to retrieve the middleware's current public ECDH key
    GET /api/middleware/public-key
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """Retrieve the server's current public key for ECDH"""
        try:
            # Get the current active middleware key
            middleware_key = MiddlewareKey.objects.filter(is_active=True).order_by('-created_at').first()
            
            if not middleware_key:
                logger.error("❌ No active middleware key found")
                return Response(
                    {"error": "No active middleware key found"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Return the public key PEM in base64 encoding
            public_key_b64 = base64.b64encode(middleware_key.public_key_pem.encode()).decode()
            
            logger.info(f"✅ Middleware public key requested from {self.get_client_ip(request)}")
            
            return Response({
                "public_key": public_key_b64,
                "key_id": middleware_key.id,
                "algorithm": "ECDH",
                "curve": "P-384",
                "created_at": middleware_key.created_at.isoformat(),
                "fingerprint": middleware_key.fingerprint
            })
            
        except Exception as e:
            logger.error(f"❌ Error retrieving middleware public key: {str(e)}")
            return Response(
                {"error": f"Failed to retrieve middleware public key: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self, request):
        """Extract client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class SecureGatewayView(APIView):
    """
    Secure Gateway for encrypted and signed payloads
    POST /api/secure/gateway
    """
    permission_classes = [AllowAny]  # Initial request won't have auth token
    
    def post(self, request):
        """
        Process an encrypted and signed payload
        
        Expected request format:
        {
            "ephemeral_pubkey": "<Base64 PEM>",
            "ciphertext": "<Base64>",
            "iv": "<Base64>"
        }
        """
        start_time = time.time()
        tx_id = f"tx_{int(timezone.now().timestamp())}"
        
        try:
            logger.info(f"🔐 Processing secure gateway request [{tx_id}] from {self.get_client_ip(request)}")
            
            # Extract request data
            data = request.data
            
            # Validate required fields
            required_fields = ['ephemeral_pubkey', 'ciphertext', 'iv']
            for field in required_fields:
                if field not in data:
                    return Response(
                        {"error": f"Missing required field: {field}"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Decode base64 data
            try:
                ephemeral_pubkey_pem = base64.b64decode(data['ephemeral_pubkey'])
                ciphertext = base64.b64decode(data['ciphertext'])
                iv = base64.b64decode(data['iv'])
            except Exception as e:
                logger.error(f"❌ Base64 decoding failed: {str(e)}")
                return Response(
                    {"error": f"Invalid base64 encoding: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Load ephemeral public key
            try:
                ephemeral_pubkey = load_pem_public_key(ephemeral_pubkey_pem)
            except Exception as e:
                logger.error(f"❌ Failed to load ephemeral public key: {str(e)}")
                return Response(
                    {"error": f"Invalid ephemeral public key: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get server's private key
            middleware_key = MiddlewareKey.objects.filter(is_active=True).order_by('-created_at').first()
            if not middleware_key:
                logger.error("❌ No active middleware key found")
                return Response(
                    {"error": "Server key not available"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Load server's private key
            try:
                server_private_key = load_pem_private_key(
                    middleware_key.private_key_pem.encode()
                )
            except Exception as e:
                logger.error(f"❌ Failed to load server private key: {str(e)}")
                return Response(
                    {"error": "Server key error"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            # Derive shared session key using ECDH + HKDF
            try:
                session_key = derive_session_key(server_private_key, ephemeral_pubkey)
            except Exception as e:
                logger.error(f"❌ Session key derivation failed: {str(e)}")
                return Response(
                    {"error": "Key exchange failed"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Decrypt the payload using derived session key
            try:
                decrypted_data = decrypt_payload(session_key, iv, ciphertext)
                payload = json.loads(decrypted_data.decode('utf-8'))
            except Exception as e:
                logger.error(f"❌ Payload decryption failed: {str(e)}")
                return Response(
                    {"error": "Failed to decrypt payload"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Validate payload structure
            required_payload_fields = ['target', 'tx', 'sig_p', 'q_p']
            for field in required_payload_fields:
                if field not in payload:
                    return Response(
                        {"error": f"Missing required payload field: {field}"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Extract payload components
            target = payload['target']
            tx_data = payload['tx']
            client_sig = decode_signature(payload['sig_p'])
            client_pubkey_pem = payload['q_p'].encode()
            
            # Verify client's signature
            try:
                client_pubkey = load_pem_public_key(client_pubkey_pem)
                tx_bytes = json.dumps(tx_data, separators=(',', ':')).encode('utf-8')
                
                if not verify_signature(client_pubkey, tx_bytes, client_sig):
                    logger.warning(f"❌ Invalid client signature for transaction [{tx_id}]")
                    return Response(
                        {"error": "Invalid signature"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except Exception as e:
                logger.error(f"❌ Signature verification error: {str(e)}")
                return Response(
                    {"error": f"Signature verification error: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Log the transaction
            with transaction.atomic():
                # Create transaction log
                tx_log = TransactionLog.objects.create(
                    tx_id=tx_id,
                    target=target,
                    user=request.user if request.user.is_authenticated else None,
                    client_pubkey=client_pubkey_pem.decode(),
                    payload=json.dumps(tx_data),
                    signature_status=True,
                    request_ip=self.get_client_ip(request),
                    request_timestamp=timezone.now()
                )
                
                # Sign the transaction with server's key
                server_sig = sign_payload(server_private_key, tx_bytes)
                
                # Update transaction log with server signature
                tx_log.server_signature = encode_signature(server_sig)
                tx_log.processed = True
                tx_log.save()
            
            # Prepare response payload
            response_payload = {
                "tx_id": tx_id,
                "tx": tx_data,
                "sig_s": encode_signature(server_sig),
                "timestamp": timezone.now().isoformat(),
                "status": "approved"
            }
            
            # Encrypt response payload with same session key
            response_json = json.dumps(response_payload).encode('utf-8')
            response_iv, response_ciphertext = encrypt_payload(session_key, response_json)
            
            # Calculate processing time
            processing_time_ms = int((time.time() - start_time) * 1000)
            
            logger.info(f"✅ Secure gateway request [{tx_id}] processed successfully ({processing_time_ms}ms)")
            
            # Return encrypted response
            return Response({
                "iv": encode_binary(response_iv),
                "ciphertext": encode_binary(response_ciphertext),
                "tx_id": tx_id,
                "processing_time_ms": processing_time_ms
            })
            
        except Exception as e:
            processing_time_ms = int((time.time() - start_time) * 1000)
            logger.error(f"❌ Secure gateway processing error: {str(e)} ({processing_time_ms}ms)")
            return Response(
                {"error": f"Gateway processing error: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def get_client_ip(self, request):
        """Extract client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')
