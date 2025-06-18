"""
SecureCipher Crypto Engine URLs
URL routing for cryptographic API endpoints
"""

from django.urls import path
from .views import RegisterPublicKeyView, VerifySignatureView, CryptoStatusView

urlpatterns = [
    # Public key management
    path('register-key/', RegisterPublicKeyView.as_view(), name='register-public-key'),
    
    # Signature verification
    path('verify-signature/', VerifySignatureView.as_view(), name='verify-signature'),
    
    # Status and health checks
    path('crypto-status/', CryptoStatusView.as_view(), name='crypto-status'),
    
    # Alternative paths for backward compatibility
    path('status/', CryptoStatusView.as_view(), name='status'),
]
