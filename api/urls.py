from django.urls import path
from .views import get_public_key, secure_gateway, crypto_login

urlpatterns = [
    path("middleware/public-key", get_public_key),
    path("secure/gateway", secure_gateway),
    path("auth/crypto-login/", crypto_login, name="crypto_login"),
]
