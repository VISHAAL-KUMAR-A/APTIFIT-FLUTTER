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
    fitness_goal = models.CharField(max_length=50, null=True, blank=True)
    activity_level = models.CharField(max_length=50, null=True, blank=True)
    reminder_mode = models.CharField(max_length=50, null=True, blank=True)
    diet_preference = models.CharField(max_length=50, null=True, blank=True)
    workout_location = models.CharField(max_length=50, null=True, blank=True)
    equipment_preference = models.CharField(
        max_length=50, null=True, blank=True)
    workout_duration = models.CharField(max_length=50, null=True, blank=True)
    fitness_level = models.CharField(max_length=50, null=True, blank=True)

    # Email verification fields
    is_verified = models.BooleanField(default=False)
    verification_token = models.CharField(
        max_length=255, null=True, blank=True)
    verification_token_created_at = models.DateTimeField(null=True, blank=True)

    # Password reset fields
    reset_password_token = models.CharField(
        max_length=255, null=True, blank=True)
    reset_password_token_created_at = models.DateTimeField(
        null=True, blank=True)

    def generate_verification_token(self):
        self.verification_token = str(uuid.uuid4())
        self.verification_token_created_at = timezone.now()
        self.save()
        return self.verification_token

    def is_token_valid(self):
        # Token is valid for 24 hours
        if not self.verification_token_created_at:
            return False
        return timezone.now() < self.verification_token_created_at + timedelta(hours=24)

    def generate_reset_password_token(self):
        self.reset_password_token = str(uuid.uuid4())
        self.reset_password_token_created_at = timezone.now()
        self.save()
        return self.reset_password_token

    def is_reset_token_valid(self):
        # Token is valid for 1 hour
        if not self.reset_password_token_created_at:
            return False
        return timezone.now() < self.reset_password_token_created_at + timedelta(hours=1)


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


class FitnessMetrics(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='fitness_metrics')
    date = models.DateField(default=timezone.now)
    heart_rate = models.IntegerField(null=True, blank=True)
    steps = models.IntegerField(null=True, blank=True)
    calories = models.IntegerField(null=True, blank=True)
    sleep_hours = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'date')


class HealthQA(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='health_qa')
    question = models.TextField()
    answer = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class ExercisePlan(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='exercise_plans')
    plan_data = models.JSONField()  # Stores the full weekly exercise plan
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
