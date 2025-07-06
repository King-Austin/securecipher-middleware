from django.urls import path
from .views import get_public_key, secure_gateway

urlpatterns = [
    path("middleware/public-key", get_public_key),
    path("secure/gateway", secure_gateway),
]
