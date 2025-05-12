from django.db import models
import uuid
from datetime import datetime, timedelta
from django.utils import timezone
import random

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
    food_culture = models.CharField(max_length=100, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    food_openness = models.IntegerField(null=True, blank=True)  # Scale of 1-5
    # Mild, Medium, Spicy, Very Spicy
    spice_preference = models.CharField(max_length=20, null=True, blank=True)
    allergies_restrictions = models.TextField(
        null=True, blank=True)  # Store allergies and restrictions
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
    verification_code = models.CharField(max_length=5, null=True, blank=True)

    # Password reset fields
    reset_password_token = models.CharField(
        max_length=255, null=True, blank=True)
    reset_password_token_created_at = models.DateTimeField(
        null=True, blank=True)

    # New fields for friend system
    friends = models.ManyToManyField(
        'self', symmetrical=True, blank=True, related_name='user_friends')
    friend_requests_sent = models.ManyToManyField(
        'self', symmetrical=False, blank=True, related_name='friend_requests_received')

    def generate_verification_token(self):
        self.verification_token = str(uuid.uuid4())
        self.verification_token_created_at = timezone.now()
        # Generate a random 5-digit verification code
        self.verification_code = ''.join(
            [str(random.randint(0, 9)) for _ in range(5)])
        self.save()
        return self.verification_token, self.verification_code

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
    last_activity = models.DateTimeField(default=timezone.now)

    def save(self, *args, **kwargs):
        # Set expiration - 30 days for "remember me" tokens, 14 days (2 weeks) for regular tokens
        if not self.expires_at:
            if self.is_remember_me:
                self.expires_at = timezone.now() + timedelta(days=30)
            else:
                # Changed from hours=24 to days=14
                self.expires_at = timezone.now() + timedelta(days=14)
        super().save(*args, **kwargs)

    def is_valid(self):
        # Check if token has reached final expiry date first
        if timezone.now() >= self.expires_at:
            return False

        # Check if token has expired based on inactivity
        inactive_period = timezone.now() - self.last_activity
        # Changed from hours=24 to hours=48
        if inactive_period > timedelta(hours=48):
            # Token is invalid due to inactivity
            return False

        # Token is valid if it hasn't reached expiry date and user hasn't been inactive too long
        return True

    def update_activity(self):
        self.last_activity = timezone.now()
        self.save(update_fields=['last_activity'])


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


class ExerciseTip(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='exercise_tips')
    exercise_plan = models.ForeignKey(
        ExercisePlan, on_delete=models.CASCADE, related_name='tips', null=True, blank=True)
    tip_content = models.CharField(max_length=200)  # Max 2 lines, ~200 chars
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class ExerciseMetrics(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='exercise_metrics')
    date = models.DateField(default=timezone.now)
    heart_rate = models.IntegerField(null=True, blank=True)  # in bpm
    calories_burnt = models.IntegerField(null=True, blank=True)
    exercise_time = models.CharField(
        max_length=10, null=True, blank=True)  # in 00:00 format
    reps = models.IntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class WorkoutNote(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='workout_notes')
    date = models.DateField(default=timezone.now)
    note_content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date', '-created_at']


class DietPlan(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='diet_plans')
    plan_data = models.JSONField()  # Stores the full weekly diet plan
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class Group(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    category = models.CharField(max_length=50)
    created_by = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='created_groups')
    members = models.ManyToManyField(
        User, related_name='joined_groups', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    image = models.ImageField(upload_to='group_images/', null=True, blank=True)

    def __str__(self):
        return self.name


class ExerciseSet(models.Model):
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='exercise_sets')
    exercise_name = models.CharField(max_length=100)
    weight_kg = models.FloatField()
    reps = models.IntegerField()
    date = models.DateField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-date', '-created_at']

    def __str__(self):
        return f"{self.exercise_name}: {self.weight_kg}kg × {self.reps} reps"


class Message(models.Model):
    sender = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='received_messages')
    content = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"From {self.sender} to {self.recipient}: {self.content[:20]}..."
