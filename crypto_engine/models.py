"""
SecureCipher Crypto Engine Models
Database models for cryptographic key management and audit logging
"""

from django.db import models
from django.contrib.auth import get_user_model
import json
import uuid
from django.utils import timezone

User = get_user_model()

class MiddlewareKey(models.Model):
    """Middleware cryptographic keys for ECDH key exchange and signing"""
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique key identifier"
    )
    private_key_pem = models.TextField(
        help_text="PEM encoded private key (stored securely)"
    )
    public_key_pem = models.TextField(
        help_text="PEM encoded public key"
    )
    fingerprint = models.CharField(
        max_length=64,
        unique=True,
        db_index=True,
        help_text="SHA-256 hash of the public key"
    )
    key_type = models.CharField(
        max_length=20,
        default="ECDH",
        help_text="Type of key (ECDH, ECDSA, etc.)"
    )
    curve = models.CharField(
        max_length=20,
        default="P-384",
        help_text="Elliptic curve used"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this key is currently active"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When the key was generated"
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the key expires (null for no expiration)"
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        help_text="Description or purpose of this key"
    )
    
    class Meta:
        db_table = 'crypto_middleware_keys'
        indexes = [
            models.Index(fields=['is_active']),
            models.Index(fields=['fingerprint']),
            models.Index(fields=['created_at']),
        ]
        verbose_name = "Middleware Key"
        verbose_name_plural = "Middleware Keys"
        ordering = ['-created_at']
    
    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"{status} {self.key_type} Key ({self.fingerprint[:8]}...)"
    
    @property
    def is_expired(self):
        """Check if the key has expired"""
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at

class TransactionLog(models.Model):
    """Log of all secure gateway transactions"""
    tx_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        help_text="Unique transaction identifier"
    )
    target = models.CharField(
        max_length=50,
        help_text="Target service or operation"
    )
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text="User who performed the transaction"
    )
    client_pubkey = models.TextField(
        help_text="Client's public key PEM"
    )
    payload = models.TextField(
        help_text="JSON serialized transaction data"
    )
    signature_status = models.BooleanField(
        default=False,
        help_text="Whether the signature was valid"
    )
    request_ip = models.GenericIPAddressField(
        help_text="Client IP address"
    )
    request_timestamp = models.DateTimeField(
        help_text="When the request was received"
    )
    response_timestamp = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the response was sent"
    )
    processing_time_ms = models.IntegerField(
        null=True,
        blank=True,
        help_text="Processing time in milliseconds"
    )
    status = models.CharField(
        max_length=20,
        default="pending",
        help_text="Transaction status (pending, completed, failed, etc.)"
    )
    response_data = models.TextField(
        blank=True,
        help_text="JSON serialized response data"
    )
    error_message = models.TextField(
        blank=True,
        help_text="Error message if transaction failed"
    )
    
    class Meta:
        db_table = 'crypto_transaction_logs'
        indexes = [
            models.Index(fields=['request_timestamp']),
            models.Index(fields=['user']),
            models.Index(fields=['status']),
            models.Index(fields=['target']),
        ]
        verbose_name = "Transaction Log"
        verbose_name_plural = "Transaction Logs"
        ordering = ['-request_timestamp']
    
    def __str__(self):
        username = self.user.username if self.user else "Anonymous"
        return f"Transaction {self.tx_id} - {self.target} by {username}"
    
    @property
    def processing_time_display(self):
        """Return formatted processing time"""
        if self.processing_time_ms is not None:
            if self.processing_time_ms < 1000:
                return f"{self.processing_time_ms}ms"
            else:
                return f"{self.processing_time_ms/1000:.2f}s"
        return "N/A"

class UserCryptoKey(models.Model):
    """Store user's cryptographic public keys for signature verification"""
    user = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='crypto_keys',
        null=True, 
        blank=True,
        help_text="Associated user account (null for anonymous keys)"
    )
    fingerprint = models.CharField(
        max_length=64, 
        unique=True, 
        db_index=True,
        help_text="SHA-256 hash of the public key for quick identification"
    )
    public_key_jwk = models.JSONField(
        help_text="Public key in JWK format from WebCrypto API"
    )
    algorithm = models.CharField(
        max_length=20, 
        default='ECDSA',
        help_text="Cryptographic algorithm used"
    )
    curve = models.CharField(
        max_length=20, 
        default='P-384',
        help_text="Elliptic curve used for ECDSA"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this key is currently active"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When the key was first registered"
    )
    last_used = models.DateTimeField(
        auto_now=True,
        help_text="Last time this key was used for verification"
    )
    device_info = models.JSONField(
        default=dict, 
        blank=True,
        help_text="Device information for key tracking"
    )
    
    class Meta:
        db_table = 'crypto_user_keys'
        indexes = [
            models.Index(fields=['fingerprint', 'is_active']),
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_used']),
        ]
        verbose_name = "User Crypto Key"
        verbose_name_plural = "User Crypto Keys"
        ordering = ['-last_used']
    
    def __str__(self):
        username = self.user.username if self.user else "Anonymous"
        return f"CryptoKey({self.fingerprint[:8]}...) - {username}"
    
    @property
    def short_fingerprint(self):
        """Return shortened fingerprint for display"""
        return f"{self.fingerprint[:8]}...{self.fingerprint[-4:]}"


class CryptoAuditLog(models.Model):
    """Comprehensive audit trail for all cryptographic operations"""
    OPERATION_CHOICES = [
        ('register', 'Key Registration'),
        ('verify', 'Signature Verification'),
        ('encrypt', 'Data Encryption'),
        ('decrypt', 'Data Decryption'),
        ('sign', 'Data Signing'),
        ('login', 'Crypto Login'),
        ('transfer', 'Crypto Transfer'),
        ('auth', 'Authentication'),
        ('status', 'Status Check'),
    ]
    
    user = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        help_text="User who performed the operation"
    )
    fingerprint = models.CharField(
        max_length=64, 
        db_index=True,
        help_text="Public key fingerprint used"
    )
    operation = models.CharField(
        max_length=20, 
        choices=OPERATION_CHOICES,
        help_text="Type of cryptographic operation"
    )
    endpoint = models.CharField(
        max_length=200,
        help_text="API endpoint accessed"
    )
    request_id = models.CharField(
        max_length=100, 
        db_index=True,
        help_text="Unique request identifier"
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        help_text="When the operation occurred"
    )
    ip_address = models.GenericIPAddressField(
        help_text="Client IP address"
    )
    user_agent = models.TextField(
        blank=True,
        help_text="Client user agent string"
    )
    success = models.BooleanField(
        help_text="Whether the operation was successful"
    )
    error_message = models.TextField(
        blank=True,
        help_text="Error message if operation failed"
    )
    request_data = models.JSONField(
        default=dict, 
        blank=True,
        help_text="Sanitized request data for audit"
    )
    response_code = models.IntegerField(
        null=True, 
        blank=True,
        help_text="HTTP response code"
    )
    processing_time_ms = models.IntegerField(
        null=True, 
        blank=True,
        help_text="Processing time in milliseconds"
    )
    
    class Meta:
        db_table = 'crypto_audit_logs'
        indexes = [
            models.Index(fields=['fingerprint', 'timestamp']),
            models.Index(fields=['request_id']),
            models.Index(fields=['operation', 'success']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]
        verbose_name = "Crypto Audit Log"
        verbose_name_plural = "Crypto Audit Logs"
        ordering = ['-timestamp']
    
    def __str__(self):
        status = "✅" if self.success else "❌"
        return f"{status} {self.get_operation_display()} - {self.fingerprint[:8]}... at {self.timestamp}"
    
    @property
    def duration_display(self):
        """Return formatted processing duration"""
        if self.processing_time_ms is not None:
            if self.processing_time_ms < 1000:
                return f"{self.processing_time_ms}ms"
            else:
                return f"{self.processing_time_ms/1000:.2f}s"
        return "N/A"
