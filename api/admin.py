from django.contrib import admin
from .models import MiddlewareKey, UsedNonce

@admin.register(MiddlewareKey)
class MiddlewareKeyAdmin(admin.ModelAdmin):
    """
    Admin interface for managing the middleware's cryptographic keys.
    Displays key information and when it was created/updated.
    """
    list_display = ('label', 'created_at', 'updated_at')
    readonly_fields = ('public_key_pem', 'private_key_pem', 'created_at', 'updated_at')
    search_fields = ('label',)

@admin.register(UsedNonce)
class UsedNonceAdmin(admin.ModelAdmin):
    """
    Admin interface for viewing nonces that have been used in transactions.
    This is critical for monitoring and detecting potential replay attacks.
    """
    list_display = ('nonce', 'timestamp')
    readonly_fields = ('nonce', 'timestamp')
    search_fields = ('nonce',)

