from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password


class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'confirm_password',
                  'name', 'age', 'gender', 'height', 'weight', 'fitness_goal', 'activity_level', 'reminder_mode']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        # Remove confirm_password if it exists in validated_data
        if 'confirm_password' in validated_data:
            validated_data.pop('confirm_password')

        # Hash the password before saving
        validated_data['password'] = make_password(
            validated_data.get('password'))
        return super().create(validated_data)
