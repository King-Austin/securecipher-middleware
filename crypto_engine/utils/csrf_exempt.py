"""
CSRF Exemption Utility
Provides decorators and mixins to exempt views from CSRF protection
"""

from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator


def csrf_exempt_view(view_func):
    """
    Decorator to make a view exempt from CSRF protection
    
    Args:
        view_func: The view function to exempt
        
    Returns:
        The decorated view function
    """
    return csrf_exempt(view_func)


class CSRFExemptMixin:
    """
    Mixin to make a class-based view exempt from CSRF protection
    """
    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)
