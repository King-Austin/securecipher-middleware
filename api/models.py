from django.db import models

class MiddlewareKey(models.Model):
    label = models.CharField(max_length=50, unique=True)
    private_key_pem = models.TextField()
    public_key_pem = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.label
