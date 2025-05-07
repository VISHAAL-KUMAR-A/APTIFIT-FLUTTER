from rest_framework import serializers
from .models import User, FitnessMetrics, HealthQA, ExercisePlan, ExerciseTip, ExerciseMetrics, WorkoutNote, DietPlan, Group, ExerciseSet
from django.contrib.auth.hashers import make_password


class UserSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'confirm_password',
                  'name', 'age', 'gender', 'height', 'weight', 'fitness_goal', 'activity_level', 'reminder_mode', 'diet_preference', 'workout_location', 'equipment_preference', 'workout_duration', 'fitness_level', 'food_culture', 'country', 'food_openness', 'spice_preference', 'allergies_restrictions']
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


class FitnessMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = FitnessMetrics
        fields = ['id', 'date', 'heart_rate',
                  'steps', 'calories', 'sleep_hours']


class HealthQASerializer(serializers.ModelSerializer):
    class Meta:
        model = HealthQA
        fields = ['id', 'question', 'answer', 'created_at']


class ExercisePlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExercisePlan
        fields = ['id', 'plan_data', 'created_at']


class ExerciseTipSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExerciseTip
        fields = ['id', 'tip_content', 'created_at']


class ExerciseMetricsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExerciseMetrics
        fields = ['id', 'date', 'heart_rate', 'calories_burnt',
                  'exercise_time', 'reps', 'created_at']


class WorkoutNoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkoutNote
        fields = ['id', 'date', 'note_content', 'created_at', 'updated_at']


class DietPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = DietPlan
        fields = ['id', 'plan_data', 'created_at']


class GroupSerializer(serializers.ModelSerializer):
    member_count = serializers.SerializerMethodField()

    class Meta:
        model = Group
        fields = ['id', 'name', 'description', 'category', 'created_by',
                  'created_at', 'updated_at', 'image', 'member_count']
        read_only_fields = ['created_by', 'created_at', 'updated_at']

    def get_member_count(self, obj):
        return obj.members.count()


class ExerciseSetSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExerciseSet
        fields = ['id', 'exercise_name', 'weight_kg',
                  'reps', 'date', 'created_at']
