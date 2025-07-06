from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
]
# Note: The 'api.urls' module should contain the URL patterns for the API endpoints.