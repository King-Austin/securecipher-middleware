from django.db import models

class MiddlewareKey(models.Model):
    label = models.CharField(max_length=50, unique=True)
    private_key_pem = models.TextField()
    public_key_pem = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.label

class UsedNonce(models.Model):
    """Stores nonces that have been used to prevent replay attacks."""
    nonce = models.CharField(max_length=100, unique=True, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.nonce
