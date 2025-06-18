"""
SecureCipher Crypto Engine Admin
Django admin interface for crypto key and audit log management
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from .models import UserCryptoKey, CryptoAuditLog

@admin.register(UserCryptoKey)
class UserCryptoKeyAdmin(admin.ModelAdmin):
    list_display = [
        'short_fingerprint_display', 'user', 'algorithm', 'curve', 
        'is_active', 'created_at', 'last_used', 'device_info_summary'
    ]
    list_filter = ['algorithm', 'curve', 'is_active', 'created_at']
    search_fields = ['fingerprint', 'user__username', 'user__email']
    readonly_fields = [
        'fingerprint', 'public_key_jwk', 'created_at', 
        'last_used', 'short_fingerprint_display'
    ]
    ordering = ['-last_used']
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Key Information', {
            'fields': ('fingerprint', 'short_fingerprint_display', 'algorithm', 'curve', 'is_active')
        }),
        ('User Association', {
            'fields': ('user',)
        }),
        ('Cryptographic Data', {
            'fields': ('public_key_jwk',),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'last_used', 'device_info'),
            'classes': ('collapse',)
        }),
    )
    
    def short_fingerprint_display(self, obj):
        """Display shortened fingerprint with copy button"""
        return format_html(
            '<code title="{}" style="cursor: pointer;">{}</code>',
            obj.fingerprint,
            obj.short_fingerprint
        )
    short_fingerprint_display.short_description = 'Fingerprint'
    
    def device_info_summary(self, obj):
        """Display device info summary"""
        if not obj.device_info:
            return '-'
        
        ip = obj.device_info.get('ip_address', 'Unknown')
        ua_parts = obj.device_info.get('user_agent', '').split()
        browser = ua_parts[0] if ua_parts else 'Unknown'
        
        return format_html(
            '<span title="{}">IP: {} | Browser: {}</span>',
            obj.device_info.get('user_agent', ''),
            ip,
            browser
        )
    device_info_summary.short_description = 'Device Info'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


@admin.register(CryptoAuditLog)
class CryptoAuditLogAdmin(admin.ModelAdmin):
    list_display = [
        'timestamp', 'operation', 'success_indicator', 'short_fingerprint', 
        'user', 'endpoint', 'ip_address', 'duration_display'
    ]
    list_filter = [
        'operation', 'success', 'timestamp', 
        ('user', admin.RelatedOnlyFieldListFilter)
    ]
    search_fields = [
        'fingerprint', 'request_id', 'endpoint', 'ip_address', 
        'user__username', 'error_message'
    ]
    readonly_fields = [
        'user', 'fingerprint', 'operation', 'endpoint', 'request_id',
        'timestamp', 'ip_address', 'user_agent', 'success', 'error_message',
        'request_data', 'response_code', 'processing_time_ms', 'duration_display'
    ]
    ordering = ['-timestamp']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Operation Details', {
            'fields': ('operation', 'success', 'timestamp', 'duration_display')
        }),
        ('Request Information', {
            'fields': ('endpoint', 'request_id', 'response_code')
        }),
        ('User & Key', {
            'fields': ('user', 'fingerprint')
        }),
        ('Client Information', {
            'fields': ('ip_address', 'user_agent'),
            'classes': ('collapse',)
        }),
        ('Error Details', {
            'fields': ('error_message',),
            'classes': ('collapse',)
        }),
        ('Request Data', {
            'fields': ('request_data',),
            'classes': ('collapse',)
        }),
    )
    
    def success_indicator(self, obj):
        """Display success status with colored indicator"""
        if obj.success:
            return format_html(
                '<span style="color: green; font-weight: bold;">✅ Success</span>'
            )
        else:
            return format_html(
                '<span style="color: red; font-weight: bold;">❌ Failed</span>'
            )
    success_indicator.short_description = 'Status'
    success_indicator.admin_order_field = 'success'
    
    def short_fingerprint(self, obj):
        """Display shortened fingerprint"""
        if len(obj.fingerprint) > 16:
            return format_html(
                '<code title="{}">{}</code>',
                obj.fingerprint,
                f"{obj.fingerprint[:8]}...{obj.fingerprint[-4:]}"
            )
        return format_html('<code>{}</code>', obj.fingerprint)
    short_fingerprint.short_description = 'Fingerprint'
    short_fingerprint.admin_order_field = 'fingerprint'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')
    
    def has_add_permission(self, request):
        """Audit logs should not be manually added"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Audit logs should not be modified"""
        return False


# Admin site customization
admin.site.site_header = "SecureCipher Middleware Administration"
admin.site.site_title = "SecureCipher Admin"
admin.site.index_title = "Cryptographic Operations Management"
