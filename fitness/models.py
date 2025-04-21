from django.db import models
import uuid
from datetime import datetime, timedelta
from django.utils import timezone

# Create your models here.


class User(models.Model):
    email = models.EmailField(max_length=200, unique=True)
    password = models.CharField(max_length=200)
    # Optional fields that can be null/blank
    name = models.CharField(max_length=200, null=True, blank=True)
    age = models.IntegerField(null=True, blank=True)
    gender = models.CharField(max_length=200, null=True, blank=True)
    height = models.IntegerField(null=True, blank=True)
    weight = models.IntegerField(null=True, blank=True)


class Token(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='tokens')
    token = models.CharField(max_length=255, unique=True, default=uuid.uuid4)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_remember_me = models.BooleanField(default=False)

    def save(self, *args, **kwargs):
        # Set expiration - 30 days for "remember me" tokens, 24 hours for regular tokens
        if not self.expires_at:
            if self.is_remember_me:
                self.expires_at = timezone.now() + timedelta(days=30)
            else:
                self.expires_at = timezone.now() + timedelta(hours=24)
        super().save(*args, **kwargs)

    def is_valid(self):
        return timezone.now() < self.expires_at
