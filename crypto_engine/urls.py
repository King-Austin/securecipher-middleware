"""
SecureCipher Crypto Engine URLs
URL routing for cryptographic API endpoints
"""

from django.urls import path
from .views import RegisterPublicKeyView, VerifySignatureView, CryptoStatusView
from .gateway import MiddlewarePublicKeyView, SecureGatewayView

urlpatterns = [
    # Public key management
    path('middleware/public-key/', MiddlewarePublicKeyView.as_view(), name='middleware-public-key'),
    
    # Secure gateway
    path('secure/gateway/', SecureGatewayView.as_view(), name='secure-gateway'),
    
    # Signature verification
    path('verify-signature/', VerifySignatureView.as_view(), name='verify-signature'),
    
    # Status and health checks
    path('crypto-status/', CryptoStatusView.as_view(), name='crypto-status'),
    
    # Alternative paths for backward compatibility
    path('status/', CryptoStatusView.as_view(), name='status'),
]
