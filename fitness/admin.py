from django.contrib import admin
from .models import User, Token, FitnessMetrics, HealthQA


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'name', 'is_verified',
                    'fitness_goal', 'workout_location', 'fitness_level')
    search_fields = ('email', 'name')
    list_filter = ('is_verified', 'fitness_goal',
                   'workout_location', 'fitness_level')
    readonly_fields = ('verification_token', 'verification_token_created_at',
                       'reset_password_token', 'reset_password_token_created_at')


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'token', 'created_at',
                    'expires_at', 'is_remember_me')
    search_fields = ('user__email', 'token')
    list_filter = ('is_remember_me',)


@admin.register(FitnessMetrics)
class FitnessMetricsAdmin(admin.ModelAdmin):
    list_display = ('user', 'date', 'heart_rate',
                    'steps', 'calories', 'sleep_hours')
    search_fields = ('user__email',)
    list_filter = ('date',)


@admin.register(HealthQA)
class HealthQAAdmin(admin.ModelAdmin):
    list_display = ('user', 'question', 'created_at')
    search_fields = ('user__email', 'question', 'answer')
    list_filter = ('created_at',)
