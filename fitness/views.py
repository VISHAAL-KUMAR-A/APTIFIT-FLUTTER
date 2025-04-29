from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from .models import User, Token, FitnessMetrics, HealthQA, ExercisePlan, ExerciseTip, ExerciseMetrics, WorkoutNote, DietPlan
from .serializers import UserSerializer, FitnessMetricsSerializer, HealthQASerializer, ExercisePlanSerializer, ExerciseMetricsSerializer, WorkoutNoteSerializer, DietPlanSerializer
from django.contrib.auth.hashers import make_password, check_password
import uuid
from datetime import timedelta
from django.utils import timezone
from .utils import send_verification_email, send_password_reset_email
import os
import openai
from django.conf import settings
import re
from django.http import JsonResponse


# Create your views here.


@api_view(['POST'])
def register_user(request):
    if request.method == 'POST':
        data = request.data

        # Check if required fields are present
        required_fields = ['email', 'password', 'confirm_password']
        for field in required_fields:
            if field not in data:
                return Response(
                    {"error": f"{field} is required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Check if email already exists
        if User.objects.filter(email=data.get('email')).exists():
            return Response(
                {"error": "User with this email already exists."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if passwords match
        if data.get('password') != data.get('confirm_password'):
            return Response(
                {"error": "Passwords do not match."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Create a new dictionary with only the fields we want to save
        user_data = {
            'email': data.get('email'),
            'password': data.get('password')
        }
        optional_fields = ['name', 'age', 'gender', 'height', 'weight']
        for field in optional_fields:
            if field in data:
                user_data[field] = data.get(field)

        serializer = UserSerializer(data=user_data)
        if serializer.is_valid():
            user = serializer.save()

            # Send verification email
            send_verification_email(user, request)

            return Response(
                {
                    "message": "User registered successfully. Please check your email to verify your account.",
                    "user": serializer.data
                },
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def verify_email(request, token):
    try:
        user = User.objects.get(verification_token=token)

        # Check if token is valid
        if not user.is_token_valid():
            return Response(
                {"error": "Verification link has expired. Please request a new one."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Mark user as verified
        user.is_verified = True
        user.verification_token = None
        user.verification_token_created_at = None
        user.save()

        return Response(
            {"message": "Email verification successful. You can now log in."},
            status=status.HTTP_200_OK
        )

    except User.DoesNotExist:
        return Response(
            {"error": "Invalid verification token."},
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['POST'])
def resend_verification(request):
    if request.method == 'POST':
        data = request.data

        if 'email' not in data:
            return Response(
                {"error": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=data.get('email'))

            # Check if user is already verified
            if user.is_verified:
                return Response(
                    {"message": "Email is already verified."},
                    status=status.HTTP_200_OK
                )

            # Send verification email
            send_verification_email(user, request)

            return Response(
                {"message": "Verification email has been resent."},
                status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"error": "No account found with this email."},
                status=status.HTTP_404_NOT_FOUND
            )


@api_view(['POST'])
def login_user(request):
    if request.method == 'POST':
        data = request.data

        # Check if email and password are provided
        if 'email' not in data or 'password' not in data:
            return Response(
                {"error": "Email and password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check if user with provided email exists
        try:
            user = User.objects.get(email=data.get('email'))
        except User.DoesNotExist:
            return Response(
                {"error": "No account found with this email."},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if email is verified
        if not user.is_verified:
            return Response(
                {"error": "Please verify your email before logging in."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Verify password
        if check_password(data.get('password'), user.password):
            # Password is correct, generate token
            remember_me = data.get('remember_me', False)

            # Create a new token
            token = Token.objects.create(
                user=user,
                is_remember_me=remember_me
            )

            # Return user data and token
            serializer = UserSerializer(user)
            return Response({
                "message": "Login successful",
                "user": serializer.data,
                "token": token.token,
                "expires_at": token.expires_at,
                "is_remember_me": token.is_remember_me
            }, status=status.HTTP_200_OK)
        else:
            # Password is incorrect
            return Response(
                {"error": "Incorrect password."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def validate_token(request):
    if request.method == 'POST':
        data = request.data

        if 'token' not in data:
            return Response(
                {"error": "Token is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                # Remove expired token
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Token is valid, return user data
            serializer = UserSerializer(token.user)
            return Response({
                "message": "Token is valid",
                "user": serializer.data,
                "token": token.token,
                "expires_at": token.expires_at,
                "is_remember_me": token.is_remember_me
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def logout_user(request):
    if request.method == 'POST':
        data = request.data

        if 'token' not in data:
            return Response(
                {"error": "Token is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            token = Token.objects.get(token=token_str)
            token.delete()
            return Response(
                {"message": "Logged out successfully."},
                status=status.HTTP_200_OK
            )
        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def forgot_password(request):
    if request.method == 'POST':
        data = request.data

        if 'email' not in data:
            return Response(
                {"error": "Email is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        email = data.get('email')

        try:
            user = User.objects.get(email=email)

            # Send password reset email
            send_password_reset_email(user, request)

            return Response(
                {"message": "If an account with this email exists, a password reset link has been sent."},
                status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            # For security reasons, don't reveal that the email doesn't exist
            # Return the same message as if the email was found
            return Response(
                {"message": "If an account with this email exists, a password reset link has been sent."},
                status=status.HTTP_200_OK
            )


@api_view(['GET', 'POST'])
def reset_password(request, token=None):
    # GET request is used to verify the token
    if request.method == 'GET':
        try:
            user = User.objects.get(reset_password_token=token)

            # Check if token is valid
            if not user.is_reset_token_valid():
                return Response(
                    {"error": "Password reset link has expired. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            return Response(
                {"message": "Token is valid. You can now reset your password."},
                status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"error": "Invalid password reset token."},
                status=status.HTTP_400_BAD_REQUEST
            )

    # POST request is used to update the password
    elif request.method == 'POST':
        data = request.data

        if 'password' not in data or 'confirm_password' not in data:
            return Response(
                {"error": "Password and confirm password are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if data.get('password') != data.get('confirm_password'):
            return Response(
                {"error": "Passwords do not match."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(reset_password_token=token)

            # Check if token is valid
            if not user.is_reset_token_valid():
                return Response(
                    {"error": "Password reset link has expired. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update password
            user.password = make_password(data.get('password'))
            user.reset_password_token = None
            user.reset_password_token_created_at = None
            user.save()

            return Response(
                {"message": "Password has been reset successfully. You can now log in with your new password."},
                status=status.HTTP_200_OK
            )

        except User.DoesNotExist:
            return Response(
                {"error": "Invalid password reset token."},
                status=status.HTTP_400_BAD_REQUEST
            )


@api_view(['POST'])
def update_user_name(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if name is provided
        if 'name' not in data:
            return Response(
                {"error": "Name is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if name is already set (only first-time users can set their name)
            if user.name:
                return Response(
                    {"error": "Name is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user name
            user.name = data.get('name')
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Name updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_user_age(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if age is provided
        if 'age' not in data:
            return Response(
                {"error": "Age is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if age is already set (only first-time users can set their age)
            if user.age is not None:
                return Response(
                    {"error": "Age is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate that age is a positive integer
            try:
                age = int(data.get('age'))
                if age <= 0:
                    return Response(
                        {"error": "Age must be a positive number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except ValueError:
                return Response(
                    {"error": "Age must be a valid number."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user age
            user.age = age
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Age updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_user_gender(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if gender is provided
        if 'gender' not in data:
            return Response(
                {"error": "Gender is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if gender is already set (only first-time users can set their gender)
            if user.gender is not None and user.gender != '':
                return Response(
                    {"error": "Gender is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate gender input (you can customize this validation based on your requirements)
            gender = data.get('gender').strip()
            if not gender:
                return Response(
                    {"error": "Gender cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Optional: Add validation for specific gender values if needed
            valid_genders = ['male', 'female',
                             'non-binary', 'other', 'prefer not to say']
            if gender.lower() not in valid_genders:
                return Response(
                    {"error": f"Gender must be one of: {', '.join(valid_genders)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user gender
            user.gender = gender.lower()
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Gender updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_user_height(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if height and unit are provided
        if 'height' not in data:
            return Response(
                {"error": "Height is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get unit, default to cm if not provided
        unit = data.get('unit', 'cm').lower()
        if unit not in ['cm', 'in']:
            return Response(
                {"error": "Unit must be either 'cm' or 'in'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if height is already set (only first-time users can set their height)
            if user.height is not None:
                return Response(
                    {"error": "Height is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate that height is a positive number
            try:
                height = float(data.get('height'))
                if height <= 0:
                    return Response(
                        {"error": "Height must be a positive number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Convert inches to cm if needed
                if unit == 'in':
                    height = round(height * 2.54)  # 1 inch = 2.54 cm
                else:
                    height = round(height)  # Round to nearest cm

                # Optional: Add a reasonable range check (e.g., 50-300 cm)
                if height < 50 or height > 300:
                    return Response(
                        {"error": "Height must be between 50 and 300 cm (19.7 and 118.1 inches)."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except ValueError:
                return Response(
                    {"error": "Height must be a valid number."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user height (always stored in cm)
            user.height = height
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Height updated successfully.",
                "user": serializer.data,
                "stored_unit": "cm" if unit == 'cm' else "in"
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_user_weight(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if weight is provided
        if 'weight' not in data:
            return Response(
                {"error": "Weight is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get unit, default to kg if not provided
        unit = data.get('unit', 'kg').lower()
        if unit not in ['kg', 'lbs']:
            return Response(
                {"error": "Unit must be either 'kg' or 'lbs'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if weight is already set (only first-time users can set their weight)
            if user.weight is not None:
                return Response(
                    {"error": "Weight is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate that weight is a positive number
            try:
                weight = float(data.get('weight'))
                if weight <= 0:
                    return Response(
                        {"error": "Weight must be a positive number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Convert lbs to kg if needed
                if unit == 'lbs':
                    weight = round(weight * 0.453592)  # 1 lbs = 0.453592 kg
                else:
                    weight = round(weight)  # Round to nearest kg

                # Optional: Add a reasonable range check (e.g., 20-500 kg)
                if weight < 20 or weight > 500:
                    return Response(
                        {"error": "Weight must be between 20 and 500 kg (44 and 1102 lbs)."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except ValueError:
                return Response(
                    {"error": "Weight must be a valid number."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user weight (always stored in kg)
            user.weight = weight
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Weight updated successfully.",
                "user": serializer.data,
                "stored_unit": "kg" if unit == 'kg' else "lbs"
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def calculate_bmi(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if height and weight are set
            if user.height is None or user.weight is None:
                missing_fields = []
                if user.height is None:
                    missing_fields.append("height")
                if user.weight is None:
                    missing_fields.append("weight")

                return Response(
                    {"error": f"Missing required fields: {', '.join(missing_fields)}. Please update your profile."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Calculate BMI: weight(kg) / (height(m))^2
            height_m = user.height / 100  # Convert cm to m
            bmi = user.weight / (height_m ** 2)
            bmi = round(bmi, 2)  # Round to 2 decimal places

            # Determine BMI category
            category = get_bmi_category(bmi)

            # Get AI comments on BMI
            ai_comment = get_openai_bmi_comment(bmi, category, user)

            return Response({
                "bmi": bmi,
                "category": category,
                "comment": ai_comment,
                "height_cm": user.height,
                "weight_kg": user.weight
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


def get_bmi_category(bmi):
    if bmi < 18.5:
        return "Underweight"
    elif 18.5 <= bmi < 25:
        return "Normal weight"
    elif 25 <= bmi < 30:
        return "Overweight"
    else:
        return "Obese"


def get_openai_bmi_comment(bmi, category, user):
    try:
        # Get OpenAI API key from environment variables
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return "BMI analysis comment not available."

        # Using project API key requires specific configuration
        client = openai.OpenAI(
            api_key=api_key
        )

        # Prepare user information for context
        user_info = f"Age: {user.age if user.age else 'Unknown'}, "
        user_info += f"Gender: {user.gender if user.gender else 'Unknown'}"

        # Create prompt for OpenAI - updated to specify shorter response with no newlines
        prompt = f"Provide a very brief (50-70 words max), personalized health comment about a person with a BMI of {bmi} " \
            f"which falls in the '{category}' category. {user_info}. " \
            f"Include concise advice. DO NOT use any line breaks or newline characters in your response. Keep it as a single paragraph with a positive tone."

        # Call OpenAI API
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful fitness assistant providing very concise BMI analysis. Keep responses under 70 words with NO newlines."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=35,  # Reduced from 150 to enforce brevity
            temperature=0.7
        )

        # Get the response and remove any newlines that might still appear
        comment = response.choices[0].message.content.strip()
        comment = comment.replace('\n', ' ').replace('  ', ' ')

        return comment

    except Exception as e:
        # Log the error (in a production environment)
        print(f"Error getting OpenAI comment: {str(e)}")
        return f"Your BMI is {bmi}, which is classified as '{category}'. For personalized advice, please consult a healthcare professional."


@api_view(['POST'])
def update_fitness_goal(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if fitness goal is provided
        if 'fitness_goal' not in data:
            return Response(
                {"error": "Fitness goal is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if fitness goal is already set
            if user.fitness_goal is not None and user.fitness_goal != '':
                return Response(
                    {"error": "Fitness goal is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate fitness goal input
            fitness_goal = data.get('fitness_goal').strip()
            if not fitness_goal:
                return Response(
                    {"error": "Fitness goal cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate allowed fitness goals
            valid_goals = ['Lose Weight', 'Build Muscle', 'Improve Sleep',
                           'Increase Endurance', 'Boost Overall Health', 'Other']
            if fitness_goal not in valid_goals:
                return Response(
                    {"error": f"Fitness goal must be one of: {', '.join(valid_goals)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user fitness goal
            user.fitness_goal = fitness_goal
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Fitness goal updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_activity_level(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if activity_level is provided
        if 'activity_level' not in data:
            return Response(
                {"error": "Activity level is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if activity level is already set
            if user.activity_level is not None and user.activity_level != '':
                return Response(
                    {"error": "Activity level is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate activity level input
            activity_level = data.get('activity_level').strip()
            if not activity_level:
                return Response(
                    {"error": "Activity level cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate allowed activity levels
            valid_levels = [
                'Sedentary-mostly sitting(little or no exercise)',
                'Lightly Active-Light exercise/sports 1-3 days/week',
                'Moderately Active-Moderate exercise/sports 3-5 days/week',
                'Very Active-Hard exercise/sports 6-7days/week'
            ]

            if activity_level not in valid_levels:
                return Response(
                    {"error": f"Activity level must be one of: {', '.join(valid_levels)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user activity level
            user.activity_level = activity_level
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Activity level updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_reminder_mode(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if reminder_mode is provided
        if 'reminder_mode' not in data:
            return Response(
                {"error": "Reminder mode is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if reminder mode is already set
            if user.reminder_mode is not None and user.reminder_mode != '':
                return Response(
                    {"error": "Reminder mode is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate reminder mode input
            reminder_mode = data.get('reminder_mode').strip()
            if not reminder_mode:
                return Response(
                    {"error": "Reminder mode cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate allowed reminder modes
            valid_modes = [
                'Chill Mode-A couple of gentle reminders per day',
                'Active Mode-Regular check-ins to keep you on track',
                'Beast Mode-Frequent nudges for a rigorous schedule'
            ]

            if reminder_mode not in valid_modes:
                return Response(
                    {"error": f"Reminder mode must be one of: {', '.join(valid_modes)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user reminder mode
            user.reminder_mode = reminder_mode
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Reminder mode updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_diet_preference(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if diet_preference is provided
        if 'diet_preference' not in data:
            return Response(
                {"error": "Diet preference is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if diet preference is already set
            if user.diet_preference is not None and user.diet_preference != '':
                return Response(
                    {"error": "Diet preference is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate diet preference input
            diet_preference = data.get('diet_preference').strip()
            if not diet_preference:
                return Response(
                    {"error": "Diet preference cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate allowed diet preferences
            valid_preferences = [
                'No Preference',
                'Vegeterian',
                'Vegan',
                'Non-Vegeterian',
                'Low-carb',
                'Keto',
                'Other'
            ]

            if diet_preference not in valid_preferences:
                return Response(
                    {"error": f"Diet preference must be one of: {', '.join(valid_preferences)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user diet preference
            user.diet_preference = diet_preference
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Diet preference updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def calculate_bmr_and_ideal_weight(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if height, weight, age, and gender are set
            missing_fields = []
            if user.height is None:
                missing_fields.append("height")
            if user.weight is None:
                missing_fields.append("weight")
            if user.age is None:
                missing_fields.append("age")
            if user.gender is None or user.gender == '':
                missing_fields.append("gender")

            if missing_fields:
                return Response(
                    {"error": f"Missing required fields: {', '.join(missing_fields)}. Please update your profile."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get BMR and ideal weight range from OpenAI
            result = get_openai_bmr_and_ideal_weight(user)

            return Response(result, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


def get_openai_bmr_and_ideal_weight(user):
    try:
        # Get OpenAI API key from environment variables
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return {
                "error": "BMR and ideal weight calculation not available.",
                "bmr": None,
                "ideal_weight_range": None
            }

        # Using project API key requires specific configuration
        client = openai.OpenAI(
            api_key=api_key
        )

        # Prepare user information for context
        user_info = (
            f"Age: {user.age}, "
            f"Gender: {user.gender}, "
            f"Height: {user.height} cm, "
            f"Weight: {user.weight} kg"
        )

        # Create prompt for OpenAI - modified to work without response_format parameter
        prompt = (
            f"For a person with the following information: {user_info}, calculate their BMR "
            f"(Basal Metabolic Rate) and ideal weight range. "
            f"Please provide the results with BMR as a number in calories per day, "
            f"and ideal weight range as a string in kg (e.g., '60-65 kg'). "
            f"Return ONLY a valid JSON object with keys 'bmr' (number) and 'ideal_weight_range' (string). "
            f"No explanations or additional text."
        )

        # Call OpenAI API without the response_format parameter
        response = client.chat.completions.create(
            model="gpt-4",  # Using GPT-4 for more accurate calculations
            messages=[
                {"role": "system", "content": "You are a fitness expert that calculates BMR and ideal weight range. Respond with a JSON object only with keys 'bmr' and 'ideal_weight_range'. No explanations."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=150,
            temperature=0.5
        )

        # Parse the response
        result = response.choices[0].message.content.strip()
        import json

        # Handle potential JSON parsing issues
        try:
            parsed_result = json.loads(result)
        except json.JSONDecodeError:
            # If the response isn't valid JSON, try to extract the JSON part
            import re
            json_match = re.search(r'({.*})', result, re.DOTALL)
            if json_match:
                try:
                    parsed_result = json.loads(json_match.group(1))
                except:
                    return {
                        "bmr": None,
                        "ideal_weight_range": None,
                        "error": "Failed to parse AI response. Please try again."
                    }
            else:
                return {
                    "bmr": None,
                    "ideal_weight_range": None,
                    "error": "Failed to parse AI response. Please try again."
                }

        # Ensure we have the expected keys
        if 'bmr' not in parsed_result or 'ideal_weight_range' not in parsed_result:
            return {
                "bmr": None,
                "ideal_weight_range": None,
                "error": "Failed to calculate BMR and ideal weight range."
            }

        # Ensure BMR is a number
        try:
            parsed_result['bmr'] = float(parsed_result['bmr'])
        except (ValueError, TypeError):
            # If BMR isn't a number, try to extract it
            if isinstance(parsed_result['bmr'], str):
                import re
                bmr_match = re.search(r'(\d+(?:\.\d+)?)', parsed_result['bmr'])
                if bmr_match:
                    parsed_result['bmr'] = float(bmr_match.group(1))
                else:
                    parsed_result['bmr'] = None

        # Add activity level to the response if available
        if user.activity_level:
            parsed_result["activity_level"] = user.activity_level

        return parsed_result

    except Exception as e:
        # Log the error (in a production environment)
        print(f"Error getting OpenAI BMR and ideal weight: {str(e)}")
        return {
            "bmr": None,
            "ideal_weight_range": None,
            "error": "Failed to calculate BMR and ideal weight range. Please try again later."
        }


@api_view(['POST'])
def get_user_fitness_profile(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Return user's fitness profile information
            fitness_profile = {
                "fitness_goal": user.fitness_goal,
                "gender": user.gender,
                "age": user.age,
                "height": user.height,
                "weight": user.weight,
                "activity_level": user.activity_level,
                "diet_preference": user.diet_preference,
                "reminder_mode": user.reminder_mode
            }

            return Response(fitness_profile, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_fitness_metrics(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Parse date or use today's date
            date_str = data.get('date')
            if date_str:
                try:
                    date = datetime.strptime(date_str, "%Y-%m-%d").date()
                except ValueError:
                    return Response(
                        {"error": "Invalid date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                date = timezone.now().date()

            # Get or create a metrics record for this date
            metrics, created = FitnessMetrics.objects.get_or_create(
                user=user,
                date=date
            )

            # Update fields if provided in the request
            if 'heart_rate' in data:
                try:
                    heart_rate = int(data.get('heart_rate'))
                    if heart_rate < 0:
                        return Response(
                            {"error": "Heart rate must be a positive number."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    metrics.heart_rate = heart_rate
                except ValueError:
                    return Response(
                        {"error": "Heart rate must be a valid number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if 'steps' in data:
                try:
                    steps = int(data.get('steps'))
                    if steps < 0:
                        return Response(
                            {"error": "Steps must be a positive number."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    metrics.steps = steps
                except ValueError:
                    return Response(
                        {"error": "Steps must be a valid number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if 'calories' in data:
                try:
                    calories = int(data.get('calories'))
                    if calories < 0:
                        return Response(
                            {"error": "Calories must be a positive number."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    metrics.calories = calories
                except ValueError:
                    return Response(
                        {"error": "Calories must be a valid number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            if 'sleep_hours' in data:
                try:
                    sleep_hours = float(data.get('sleep_hours'))
                    if sleep_hours < 0 or sleep_hours > 24:
                        return Response(
                            {"error": "Sleep hours must be between 0 and 24."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    metrics.sleep_hours = sleep_hours
                except ValueError:
                    return Response(
                        {"error": "Sleep hours must be a valid number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Save the metrics
            metrics.save()

            # Return the updated metrics
            serializer = FitnessMetricsSerializer(metrics)
            return Response({
                "message": "Fitness metrics updated successfully.",
                "metrics": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def get_fitness_metrics(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Parse date parameters
            start_date_str = data.get('start_date')
            end_date_str = data.get('end_date')

            # Filter by date range if provided
            if start_date_str and end_date_str:
                try:
                    start_date = datetime.strptime(
                        start_date_str, "%Y-%m-%d").date()
                    end_date = datetime.strptime(
                        end_date_str, "%Y-%m-%d").date()

                    metrics = FitnessMetrics.objects.filter(
                        user=user,
                        date__gte=start_date,
                        date__lte=end_date
                    ).order_by('-date')

                except ValueError:
                    return Response(
                        {"error": "Invalid date format. Use YYYY-MM-DD."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                # Get metrics for the last 7 days if no date range is specified
                end_date = timezone.now().date()
                start_date = end_date - timedelta(days=6)

                metrics = FitnessMetrics.objects.filter(
                    user=user,
                    date__gte=start_date,
                    date__lte=end_date
                ).order_by('-date')

            # Serialize and return the metrics
            serializer = FitnessMetricsSerializer(metrics, many=True)
            return Response({
                "message": "Fitness metrics retrieved successfully.",
                "metrics": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def health_question(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if question is provided
        if 'question' not in data or not data.get('question').strip():
            return Response(
                {"error": "Question is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user
            question = data.get('question').strip()

            # Get user profile data for context
            user_profile = {
                "name": user.name,
                "age": user.age,
                "gender": user.gender,
                "height": user.height,
                "weight": user.weight,
                "fitness_goal": user.fitness_goal,
                "activity_level": user.activity_level,
                "diet_preference": user.diet_preference
            }

            # Get recent fitness metrics if available
            recent_metrics = FitnessMetrics.objects.filter(
                user=user).order_by('-date').first()
            metrics_data = {}
            if recent_metrics:
                metrics_data = {
                    "heart_rate": recent_metrics.heart_rate,
                    "steps": recent_metrics.steps,
                    "calories": recent_metrics.calories,
                    "sleep_hours": recent_metrics.sleep_hours
                }

            # Get answer from GPT-4
            answer = get_gpt_health_answer(
                question, user_profile, metrics_data)

            # Store the Q&A in the database
            health_qa = HealthQA.objects.create(
                user=user,
                question=question,
                answer=answer
            )

            return Response({
                "question": question,
                "answer": answer
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def get_health_qa_history(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Get Q&A history for the user
            history = HealthQA.objects.filter(user=user)

            # Apply pagination if specified
            page_size = data.get('page_size', 10)
            page = data.get('page', 1)

            try:
                page_size = int(page_size)
                page = int(page)

                if page_size <= 0 or page <= 0:
                    raise ValueError

                start = (page - 1) * page_size
                end = start + page_size
                history = history[start:end]

            except (ValueError, TypeError):
                return Response(
                    {"error": "Invalid pagination parameters."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Serialize and return the history
            serializer = HealthQASerializer(history, many=True)
            return Response({
                "history": serializer.data,
                "page": page,
                "page_size": page_size
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


def get_gpt_health_answer(question, user_profile, metrics_data):
    try:
        # Get OpenAI API key from environment variables
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return "Sorry, I'm unable to process your health question at the moment. Please try again later."

        # Using project API key requires specific configuration
        client = openai.OpenAI(
            api_key=api_key
        )

        # Prepare context with user information
        context = []

        for key, value in user_profile.items():
            if value is not None and value != '':
                if key == 'height':
                    context.append(f"Height: {value} cm")
                elif key == 'weight':
                    context.append(f"Weight: {value} kg")
                else:
                    context.append(f"{key.replace('_', ' ').title()}: {value}")

        for key, value in metrics_data.items():
            if value is not None:
                if key == 'sleep_hours':
                    context.append(f"Average sleep: {value} hours")
                elif key == 'heart_rate':
                    context.append(f"Heart rate: {value} bpm")
                elif key == 'steps':
                    context.append(f"Daily steps: {value}")
                elif key == 'calories':
                    context.append(f"Daily calories burned: {value}")

        user_context = ", ".join(context)

        # Create prompt for GPT-4 - explicitly tell it not to use newlines
        system_message = (
            "You are a professional health and fitness advisor. Answer the user's question in detail, "
            "providing personalized advice based on their profile. Only answer questions related to health, "
            "fitness, nutrition, exercise, wellness, and medical topics. For any other topics, politely "
            "inform the user that you can only address health and fitness related questions. "
            "Always provide evidence-based information and add appropriate disclaimers when necessary. "
            "DO NOT include any newline characters (\\n) in your response."
        )

        user_message = (
            f"User profile: {user_context}\n\n"
            f"Question: {question}"
        )

        # Call GPT-4 API
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message}
            ],
            max_tokens=800,
            temperature=0.7
        )

        # Get the response and remove any newlines that might still appear
        answer = response.choices[0].message.content.strip()
        answer = answer.replace('\n', ' ').replace('\r', ' ')
        # Remove any double spaces that might be created after replacing newlines
        while '  ' in answer:
            answer = answer.replace('  ', ' ')

        # Check if the question is unrelated to health/fitness
        if "I can only address health" in answer or "only answer questions related to health" in answer:
            return "I can only answer questions related to health, fitness, nutrition, exercise, wellness, and medical topics. Please ask a health or fitness related question."

        return answer

    except Exception as e:
        # Log the error (in a production environment)
        print(f"Error getting GPT answer: {str(e)}")
        return "Sorry, I encountered an error processing your question. Please try again later."


@api_view(['POST'])
def update_user_profile(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user
            updated_fields = []

            # Update name if provided
            if 'name' in data:
                user.name = data.get('name')
                updated_fields.append('name')

            # Update email if provided
            if 'email' in data and data.get('email') != user.email:
                # Check if email already exists
                if User.objects.filter(email=data.get('email')).exists():
                    return Response(
                        {"error": "User with this email already exists."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                user.email = data.get('email')
                updated_fields.append('email')

            # Update age if provided
            if 'age' in data:
                try:
                    age = int(data.get('age'))
                    if age <= 0:
                        return Response(
                            {"error": "Age must be a positive number."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    user.age = age
                    updated_fields.append('age')
                except ValueError:
                    return Response(
                        {"error": "Age must be a valid number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Update gender if provided
            if 'gender' in data:
                gender = data.get('gender').strip()
                valid_genders = ['male', 'female',
                                 'non-binary', 'other', 'prefer not to say']
                if gender.lower() not in valid_genders:
                    return Response(
                        {"error": f"Gender must be one of: {', '.join(valid_genders)}"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                user.gender = gender.lower()
                updated_fields.append('gender')

            # Update height if provided
            if 'height' in data:
                try:
                    unit = data.get('height_unit', 'cm').lower()
                    if unit not in ['cm', 'in']:
                        return Response(
                            {"error": "Height unit must be either 'cm' or 'in'."},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    height = float(data.get('height'))
                    if height <= 0:
                        return Response(
                            {"error": "Height must be a positive number."},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    # Convert inches to cm if needed
                    if unit == 'in':
                        height = round(height * 2.54)  # 1 inch = 2.54 cm
                    else:
                        height = round(height)  # Round to nearest cm

                    # Optional: Add a reasonable range check
                    if height < 50 or height > 300:
                        return Response(
                            {"error": "Height must be between 50 and 300 cm (19.7 and 118.1 inches)."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    user.height = height
                    updated_fields.append('height')
                except ValueError:
                    return Response(
                        {"error": "Height must be a valid number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Update weight if provided
            if 'weight' in data:
                try:
                    unit = data.get('weight_unit', 'kg').lower()
                    if unit not in ['kg', 'lbs']:
                        return Response(
                            {"error": "Weight unit must be either 'kg' or 'lbs'."},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    weight = float(data.get('weight'))
                    if weight <= 0:
                        return Response(
                            {"error": "Weight must be a positive number."},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    # Convert lbs to kg if needed
                    if unit == 'lbs':
                        # 1 lbs = 0.453592 kg
                        weight = round(weight * 0.453592)
                    else:
                        weight = round(weight)  # Round to nearest kg

                    # Optional: Add a reasonable range check
                    if weight < 20 or weight > 500:
                        return Response(
                            {"error": "Weight must be between 20 and 500 kg (44 and 1102 lbs)."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                    user.weight = weight
                    updated_fields.append('weight')
                except ValueError:
                    return Response(
                        {"error": "Weight must be a valid number."},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Save user if any fields were updated
            if updated_fields:
                user.save()
                return Response({
                    "message": f"Profile updated successfully. Updated fields: {', '.join(updated_fields)}",
                    "user": UserSerializer(user).data
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    "message": "No fields to update were provided.",
                    "user": UserSerializer(user).data
                }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_workout_location(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if workout_location is provided
        if 'workout_location' not in data:
            return Response(
                {"error": "Workout location is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if workout location is already set (can only be set once)
            if user.workout_location is not None and user.workout_location != '':
                return Response(
                    {"error": "Workout location is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate workout location input
            workout_location = data.get('workout_location').strip()
            if not workout_location:
                return Response(
                    {"error": "Workout location cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate allowed workout locations
            valid_locations = ['At Home', 'At the GYM']
            if workout_location not in valid_locations:
                return Response(
                    {"error": f"Workout location must be one of: {', '.join(valid_locations)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user workout location
            user.workout_location = workout_location
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Workout location updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_equipment_preference(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if equipment_preference is provided
        if 'equipment_preference' not in data:
            return Response(
                {"error": "Equipment preference is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if equipment preference is already set (can only be set once)
            if user.equipment_preference is not None and user.equipment_preference != '':
                return Response(
                    {"error": "Equipment preference is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate equipment preference input
            equipment_preference = data.get('equipment_preference').strip()
            if not equipment_preference:
                return Response(
                    {"error": "Equipment preference cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate allowed equipment preferences
            valid_preferences = ['Yoga Mat', 'Dumbbells',
                                 'Resistance Bands', 'No Equipment']
            if equipment_preference not in valid_preferences:
                return Response(
                    {"error": f"Equipment preference must be one of: {', '.join(valid_preferences)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user equipment preference
            user.equipment_preference = equipment_preference
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Equipment preference updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_workout_duration(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if workout_duration is provided
        if 'workout_duration' not in data:
            return Response(
                {"error": "Workout duration is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if workout duration is already set (can only be set once)
            if user.workout_duration is not None and user.workout_duration != '':
                return Response(
                    {"error": "Workout duration is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate workout duration input
            workout_duration = data.get('workout_duration').strip()
            if not workout_duration:
                return Response(
                    {"error": "Workout duration cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate allowed workout durations
            valid_durations = ['10-15 mins', '20-30 mins', '45+ mins']
            if workout_duration not in valid_durations:
                return Response(
                    {"error": f"Workout duration must be one of: {', '.join(valid_durations)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user workout duration
            user.workout_duration = workout_duration
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Workout duration updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def update_fitness_level(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        # Check if fitness_level is provided
        if 'fitness_level' not in data:
            return Response(
                {"error": "Fitness level is required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if fitness level is already set (can only be set once)
            if user.fitness_level is not None and user.fitness_level != '':
                return Response(
                    {"error": "Fitness level is already set and cannot be changed."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate fitness level input
            fitness_level = data.get('fitness_level').strip()
            if not fitness_level:
                return Response(
                    {"error": "Fitness level cannot be empty."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate allowed fitness levels
            valid_levels = ['Beginner', 'Intermediate', 'Advanced']
            if fitness_level not in valid_levels:
                return Response(
                    {"error": f"Fitness level must be one of: {', '.join(valid_levels)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update user fitness level
            user.fitness_level = fitness_level
            user.save()

            # Return updated user data
            serializer = UserSerializer(user)
            return Response({
                "message": "Fitness level updated successfully.",
                "user": serializer.data
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def generate_weekly_exercise_plan(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Check if required fields are set
            missing_fields = []
            if user.workout_location is None or user.workout_location == '':
                missing_fields.append("workout_location")
            if user.workout_duration is None or user.workout_duration == '':
                missing_fields.append("workout_duration")
            if user.fitness_level is None or user.fitness_level == '':
                missing_fields.append("fitness_level")

            if missing_fields:
                return Response(
                    {"error": f"Missing required fields: {', '.join(missing_fields)}. Please update your profile."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get user profile data for exercise plan generation
            user_profile = {
                "age": user.age,
                "gender": user.gender,
                "height": user.height,
                "weight": user.weight,
                "fitness_goal": user.fitness_goal,
                "activity_level": user.activity_level,
                "workout_location": user.workout_location,
                "equipment_preference": user.equipment_preference,
                "workout_duration": user.workout_duration,
                "fitness_level": user.fitness_level
            }

            # Generate weekly exercise plan using GPT-4
            exercise_plan = generate_gpt_exercise_plan(user_profile)

            # Save the exercise plan to the database
            ExercisePlan.objects.create(
                user=user,
                plan_data=exercise_plan
            )

            return Response({
                "message": "Weekly exercise plan generated successfully.",
                "exercise_plan": exercise_plan
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


def generate_gpt_exercise_plan(user_profile):
    try:
        # Get OpenAI API key from environment variables
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return {"error": "Exercise plan generation is not available at the moment."}

        # Using project API key
        client = openai.OpenAI(
            api_key=api_key
        )

        # Prepare user information for context
        context = []
        for key, value in user_profile.items():
            if value is not None and value != '':
                if key == 'height':
                    context.append(f"Height: {value} cm")
                elif key == 'weight':
                    context.append(f"Weight: {value} kg")
                else:
                    context.append(f"{key.replace('_', ' ').title()}: {value}")

        user_context = ", ".join(context)

        # Create prompt for GPT-4
        system_message = (
            "You are a professional fitness trainer creating personalized weekly exercise plans. "
            "Create a detailed, structured exercise plan for the entire week (Monday through Sunday) based on the user's profile. "
            "The plan should be realistic, balanced, and aligned with the user's fitness level, goals, and constraints. "
            "For each day, provide specific exercises with sets, reps, and rest periods where applicable. "
            "Include rest days as appropriate for the user's fitness level. "
            "Format your response as a JSON object with days of the week as keys and structured workout details as values."
        )

        user_message = (
            f"Create a weekly exercise plan for a person with the following profile:\n\n"
            f"{user_context}\n\n"
            f"Please provide a detailed, structured plan for each day of the week (Monday through Sunday) "
            f"that is appropriate for this person's fitness level, workout location, equipment preference, and time constraints. "
            f"For exercise days, include specific exercises, sets, reps, and rest periods. "
            f"Include appropriate rest days based on their fitness level. "
            f"Return the plan as a JSON object where each key is a day of the week and each value contains the workout details."
        )

        # Call GPT-4 API
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message}
            ],
            max_tokens=2000,
            temperature=0.7
        )

        # Get the response and parse it
        result = response.choices[0].message.content.strip()

        # Try to parse the JSON from the response
        import json
        import re

        # First try direct JSON parsing
        try:
            exercise_plan = json.loads(result)
        except json.JSONDecodeError:
            # If that fails, try to extract the JSON part using regex
            json_match = re.search(r'({[\s\S]*})', result)
            if json_match:
                try:
                    exercise_plan = json.loads(json_match.group(1))
                except:
                    # If all parsing fails, return a structured error message
                    return {
                        "error": "Could not parse the exercise plan. Please try again.",
                        "raw_response": result
                    }
            else:
                # If no JSON-like structure is found, return the raw text
                return {
                    "error": "Could not parse the exercise plan. Please try again.",
                    "raw_response": result
                }

        return exercise_plan

    except Exception as e:
        # Log the error (in a production environment)
        print(f"Error generating exercise plan: {str(e)}")
        return {
            "error": f"Failed to generate exercise plan: {str(e)}",
            "message": "Please try again later."
        }


@api_view(['POST'])
def get_exercise_plans(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Get exercise plans for the user
            exercise_plans = ExercisePlan.objects.filter(user=user)

            # Apply pagination if specified
            page_size = data.get('page_size', 5)
            page = data.get('page', 1)

            try:
                page_size = int(page_size)
                page = int(page)

                if page_size <= 0 or page <= 0:
                    raise ValueError

                start = (page - 1) * page_size
                end = start + page_size
                exercise_plans = exercise_plans[start:end]

            except (ValueError, TypeError):
                return Response(
                    {"error": "Invalid pagination parameters."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Serialize and return the plans
            serializer = ExercisePlanSerializer(exercise_plans, many=True)
            return Response({
                "message": "Exercise plans retrieved successfully.",
                "plans": serializer.data,
                "page": page,
                "page_size": page_size
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


@api_view(['POST'])
def get_exercise_plan_tips(request):
    if request.method == 'POST':
        data = request.data

        # Check if token is provided
        if 'token' not in data:
            return Response(
                {"error": "Token is required. Please login first."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        token_str = data.get('token')

        try:
            # Validate token and get user
            token = Token.objects.get(token=token_str)

            # Check if token is expired
            if not token.is_valid():
                token.delete()
                return Response(
                    {"error": "Token has expired. Please login again."},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = token.user

            # Get the latest exercise plan
            latest_plan = ExercisePlan.objects.filter(
                user=user).order_by('-created_at').first()

            if not latest_plan:
                return Response(
                    {"error": "No exercise plan found. Generate a plan first."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Generate tips based on the exercise plan
            tips = generate_exercise_tips(user, latest_plan)

            return Response({
                "message": "Exercise plan tips retrieved successfully.",
                "tips": tips
            }, status=status.HTTP_200_OK)

        except Token.DoesNotExist:
            return Response(
                {"error": "Invalid token. Please login again."},
                status=status.HTTP_401_UNAUTHORIZED
            )


def generate_exercise_tips(user, exercise_plan):
    try:
        # Get OpenAI API key from environment variables
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            return [{"tip_content": "Remember to stay hydrated throughout your workout sessions."}]

        # Using project API key
        client = openai.OpenAI(
            api_key=api_key
        )

        # Get user profile data for context
        user_profile = {
            "age": user.age,
            "gender": user.gender,
            "fitness_goal": user.fitness_goal,
            "fitness_level": user.fitness_level
        }

        # Create prompt for GPT
        system_message = (
            "You are a fitness expert providing short, practical tips for exercise plans. "
            "Each tip must be concise (maximum 2 lines or about 100-140 characters) and specific to the user's plan. "
            "Generate EXACTLY 4 tips that are actionable, motivational, and tailored to the user's profile and plan. "
            "Format as a simple JSON array of strings, each string being one tip."
        )

        user_message = (
            f"Generate 4 concise exercise tips (maximum 2 lines each) for a user with this profile: {user_profile}\n\n"
            f"The user is following this exercise plan: {exercise_plan.plan_data}\n\n"
            f"Return ONLY a JSON array containing 4 short tips as strings. Each tip should be actionable "
            f"and directly relevant to this specific plan and user profile."
        )

        # Call GPT API
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": user_message}
            ],
            max_tokens=500,
            temperature=0.7
        )

        # Get the response and parse it
        result = response.choices[0].message.content.strip()

        # Parse the JSON from the response
        import json
        import re

        try:
            tips_list = json.loads(result)

            # If not a list or more than 4 tips, adjust
            if not isinstance(tips_list, list):
                tips_list = [
                    "Stay hydrated during workouts for better performance.",
                    "Proper form is better than more repetitions. Quality over quantity.",
                    "Schedule rest days to allow your muscles to recover and grow.",
                    "Track your progress weekly to stay motivated and see improvements."
                ]

            # Limit to 4 tips
            tips_list = tips_list[:4]

            # Store tips in database
            stored_tips = []
            for tip_content in tips_list:
                tip = ExerciseTip.objects.create(
                    user=user,
                    exercise_plan=exercise_plan,
                    tip_content=tip_content
                )
                stored_tips.append({
                    "id": tip.id,
                    "tip_content": tip.tip_content,
                    "created_at": tip.created_at
                })

            return stored_tips

        except json.JSONDecodeError:
            # If parsing fails, extract with regex or provide default tips
            json_match = re.search(r'\[(.*)\]', result, re.DOTALL)
            if json_match:
                try:
                    # Try to parse as a JSON array
                    tips_text = "[" + json_match.group(1) + "]"
                    tips_list = json.loads(tips_text)

                    # Store tips in database
                    stored_tips = []
                    for tip_content in tips_list[:4]:
                        tip = ExerciseTip.objects.create(
                            user=user,
                            exercise_plan=exercise_plan,
                            tip_content=tip_content
                        )
                        stored_tips.append({
                            "id": tip.id,
                            "tip_content": tip.tip_content,
                            "created_at": tip.created_at
                        })

                    return stored_tips
                except:
                    pass

            # Fall back to default tips
            default_tips = [
                "Stay hydrated during workouts for better performance.",
                "Proper form is better than more repetitions. Quality over quantity.",
                "Schedule rest days to allow your muscles to recover and grow.",
                "Track your progress weekly to stay motivated and see improvements."
            ]

            # Store default tips in database
            stored_tips = []
            for tip_content in default_tips:
                tip = ExerciseTip.objects.create(
                    user=user,
                    exercise_plan=exercise_plan,
                    tip_content=tip_content
                )
                stored_tips.append({
                    "id": tip.id,
                    "tip_content": tip.tip_content,
                    "created_at": tip.created_at
                })

            return stored_tips

    except Exception as e:
        # Log the error (in a production environment)
        print(f"Error generating exercise tips: {str(e)}")

        # Provide default tips
        default_tips = [
            "Stay hydrated during workouts for better performance.",
            "Proper form is better than more repetitions. Quality over quantity.",
            "Schedule rest days to allow your muscles to recover and grow.",
            "Track your progress weekly to stay motivated and see improvements."
        ]

        # Store default tips in database
        stored_tips = []
        for tip_content in default_tips:
            tip = ExerciseTip.objects.create(
                user=user,
                exercise_plan=exercise_plan,
                tip_content=tip_content
            )
            stored_tips.append({
                "id": tip.id,
                "tip_content": tip.tip_content,
                "created_at": tip.created_at
            })

        return stored_tips


@api_view(['POST'])
def record_exercise_metrics(request):
    """
    Record exercise metrics including heart rate, calories burnt, exercise time (00:00 format) and reps
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Get exercise time and validate format
    exercise_time = request.data.get('exercise_time')
    if exercise_time:
        # Optionally validate the format (should be in 00:00 format)
        if not re.match(r'^\d{2}:\d{2}$', exercise_time):
            return Response({
                'status': 'error',
                'message': 'Exercise time should be in 00:00 format'
            }, status=400)

    # Extract data from the request
    data = {
        'heart_rate': request.data.get('heart_rate'),
        'calories_burnt': request.data.get('calories_burnt'),
        'exercise_time': exercise_time,
        'reps': request.data.get('reps'),
        'date': request.data.get('date', timezone.now().date())
    }

    # Create and save the exercise metrics
    exercise_metrics = ExerciseMetrics(user=user, **data)
    exercise_metrics.save()

    # Serialize the data for response
    serializer = ExerciseMetricsSerializer(exercise_metrics)

    return Response({
        'status': 'success',
        'message': 'Exercise metrics recorded successfully',
        'data': serializer.data
    }, status=201)


@api_view(['GET'])
def get_exercise_metrics(request):
    """
    Get all exercise metrics for the authenticated user
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Get all exercise metrics for the user
    metrics = ExerciseMetrics.objects.filter(user=user)
    serializer = ExerciseMetricsSerializer(metrics, many=True)

    return Response({
        'status': 'success',
        'data': serializer.data
    })


@api_view(['POST'])
def add_workout_note(request):
    """
    Add a workout note for the authenticated user
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Extract data from the request
    note_content = request.data.get('note_content')
    if not note_content:
        return Response({
            'status': 'error',
            'message': 'Note content is required'
        }, status=400)

    date = request.data.get('date', timezone.now().date())

    # Create and save the workout note
    workout_note = WorkoutNote(
        user=user,
        date=date,
        note_content=note_content
    )
    workout_note.save()

    # Serialize the data for response
    serializer = WorkoutNoteSerializer(workout_note)

    return Response({
        'status': 'success',
        'message': 'Workout note added successfully',
        'data': serializer.data
    }, status=201)


@api_view(['GET'])
def get_workout_notes(request):
    """
    Get all workout notes for the authenticated user
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Get optional date filter
    date_filter = request.GET.get('date')

    # Get workout notes for the user, optionally filtered by date
    if date_filter:
        try:
            date_obj = datetime.strptime(date_filter, '%Y-%m-%d').date()
            notes = WorkoutNote.objects.filter(user=user, date=date_obj)
        except ValueError:
            return Response({
                'status': 'error',
                'message': 'Invalid date format. Use YYYY-MM-DD'
            }, status=400)
    else:
        notes = WorkoutNote.objects.filter(user=user)

    serializer = WorkoutNoteSerializer(notes, many=True)

    return Response({
        'status': 'success',
        'data': serializer.data
    })


@api_view(['POST'])
def update_preferences(request):
    """
    Update multiple user preferences at once
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Fields that can be updated
    updatable_fields = [
        'diet_preference',
        'fitness_goal',
        'activity_level',
        'reminder_mode',
        'workout_location',
        'workout_duration',
        'fitness_level'
    ]

    # Track which fields were updated
    updated_fields = []

    # Update each field if provided in the request
    for field in updatable_fields:
        if field in request.data:
            value = request.data.get(field)
            # Validate value (you may want to add specific validation for each field)
            if value:
                setattr(user, field, value)
                updated_fields.append(field)

    # Save the user if any fields were updated
    if updated_fields:
        user.save()
        return Response({
            'status': 'success',
            'message': f'Updated user preferences: {", ".join(updated_fields)}',
            'updated_fields': updated_fields
        })
    else:
        return Response({
            'status': 'error',
            'message': 'No valid fields provided for update'
        }, status=400)


@api_view(['POST'])
def generate_weekly_diet_plan(request):
    """
    Generate a weekly diet plan based on user's profile and preferences
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Calculate BMI if it doesn't exist yet
    if user.height and user.weight:
        height_m = user.height / 100  # Convert cm to meters
        bmi = user.weight / (height_m * height_m)
    else:
        bmi = None

    # Get additional parameters (optional)
    specific_needs = request.data.get('specific_needs', '')
    allergies = request.data.get('allergies', '')

    # Generate diet plan
    diet_plan = generate_gpt_diet_plan(user, bmi, specific_needs, allergies)

    if diet_plan:
        # Save to database
        diet_plan_obj = DietPlan(
            user=user,
            plan_data=diet_plan
        )
        diet_plan_obj.save()

        # Serialize for response
        serializer = DietPlanSerializer(diet_plan_obj)

        return Response({
            'status': 'success',
            'message': 'Weekly diet plan generated successfully',
            'data': serializer.data
        })
    else:
        return Response({
            'status': 'error',
            'message': 'Failed to generate diet plan. Please try again.'
        }, status=500)


def generate_gpt_diet_plan(user, bmi=None, specific_needs='', allergies=''):
    """
    Use OpenAI's GPT-4 to generate a diet plan based on user profile
    """
    try:
        # Get the OpenAI API key directly from environment
        openai_api_key = os.getenv('OPENAI_API_KEY')

        if not openai_api_key:
            print("Error: OpenAI API key not found in environment variables")
            return None

        # Construct user profile information
        user_profile = {
            'age': user.age if user.age else 'unknown',
            'gender': user.gender if user.gender else 'unknown',
            'height': f"{user.height} cm" if user.height else 'unknown',
            'weight': f"{user.weight} kg" if user.weight else 'unknown',
            'bmi': f"{bmi:.1f}" if bmi else 'unknown',
            'fitness_goal': user.fitness_goal if user.fitness_goal else 'general fitness',
            'activity_level': user.activity_level if user.activity_level else 'moderate',
            'diet_preference': user.diet_preference if user.diet_preference else 'no specific preference',
        }

        # For BMR calculation (if needed)
        bmr = None
        if user.gender and user.age and user.height and user.weight:
            if user.gender.lower() == 'male':
                bmr = 88.362 + (13.397 * user.weight) + \
                    (4.799 * user.height) - (5.677 * user.age)
            elif user.gender.lower() == 'female':
                bmr = 447.593 + (9.247 * user.weight) + \
                    (3.098 * user.height) - (4.330 * user.age)

            user_profile['bmr'] = f"{bmr:.0f} calories/day" if bmr else 'unknown'

        # Format the prompt for GPT-4 - with clearer instructions about JSON format
        prompt = f"""
        I need to create a personalized 7-day diet plan for a {user_profile['gender']}, {user_profile['age']} years old.
        
        User Profile:
        - Height: {user_profile['height']}
        - Weight: {user_profile['weight']}
        - BMI: {user_profile['bmi']}
        - BMR: {user_profile.get('bmr', 'unknown')}
        - Fitness Goal: {user_profile['fitness_goal']}
        - Activity Level: {user_profile['activity_level']}
        - Diet Preference: {user_profile['diet_preference']}
        """

        if specific_needs:
            prompt += f"- Specific Needs: {specific_needs}\n"

        if allergies:
            prompt += f"- Allergies/Intolerances: {allergies}\n"

        prompt += """
        Please create a detailed 7-day diet plan organized by days of the week (Monday to Sunday).
        
        IMPORTANT: You must provide a complete plan for ALL seven days, not just for Monday.
        
        For each day, include:
        1. Breakfast
        2. Morning Snack
        3. Lunch
        4. Afternoon Snack
        5. Dinner
        6. Evening Snack (optional)
        
        For each meal, include:
        - Specific food items
        - Approximate portion sizes
        - Estimated calorie count per meal
        - Key nutrients provided
        
        Also include:
        - Daily water intake recommendation
        - Total daily calorie target
        - Macronutrient breakdown (protein, carbs, fats)
        - Brief explanation of how this plan supports the user's fitness goals
        
        Format the response as a JSON object with this exact structure:
        {
          "Monday": {
            "Breakfast": {"food": "", "portion": "", "calories": 0, "nutrients": ""},
            "MorningSnack": {"food": "", "portion": "", "calories": 0, "nutrients": ""},
            "Lunch": {"food": "", "portion": "", "calories": 0, "nutrients": ""},
            "AfternoonSnack": {"food": "", "portion": "", "calories": 0, "nutrients": ""},
            "Dinner": {"food": "", "portion": "", "calories": 0, "nutrients": ""},
            "EveningSnack": {"food": "", "portion": "", "calories": 0, "nutrients": ""},
            "WaterIntake": "",
            "TotalCalories": 0,
            "MacronutrientBreakdown": {"Protein": "", "Carbs": "", "Fats": ""},
            "FitnessGoalSupport": ""
          },
          "Tuesday": {...same structure...},
          "Wednesday": {...same structure...},
          "Thursday": {...same structure...},
          "Friday": {...same structure...},
          "Saturday": {...same structure...},
          "Sunday": {...same structure...}
        }
        
        Provide the COMPLETE JSON for all days without using ellipses (...) or other placeholders. Do not include newlines or escape characters.
        """

        # Call OpenAI API with direct API key and increased tokens
        client = openai.OpenAI(api_key=openai_api_key)
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a certified nutritionist and fitness expert. Create personalized diet plans based on individual profiles."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000,  # Increased token limit
            temperature=0.7
        )

        # Parse the response
        diet_plan_text = response.choices[0].message.content

        # Extract JSON from the response
        import json
        import re

        # Try to find and parse JSON content
        json_match = re.search(r'```json\n(.*?)\n```',
                               diet_plan_text, re.DOTALL)
        if json_match:
            json_content = json_match.group(1)
            # Clean up the JSON string - remove newlines and unnecessary escapes
            json_content = json_content.replace('\n', ' ').replace('\\', '')
            diet_plan_json = json.loads(json_content)
        else:
            try:
                # Clean up the JSON string - remove newlines and unnecessary escapes
                diet_plan_text = diet_plan_text.replace(
                    '\n', ' ').replace('\\', '')
                diet_plan_json = json.loads(diet_plan_text)
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {str(e)}")
                # If not valid JSON, return as text but without newlines
                diet_plan_json = {
                    "raw_plan": diet_plan_text.replace('\n', ' ')}

        return diet_plan_json

    except Exception as e:
        print(f"Error generating diet plan: {str(e)}")
        return None


@api_view(['POST'])
def get_diet_plans(request):
    """
    Get all diet plans for the authenticated user
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Get all diet plans for the user
    diet_plans = DietPlan.objects.filter(user=user)
    serializer = DietPlanSerializer(diet_plans, many=True)

    return Response({
        'status': 'success',
        'data': serializer.data
    })


@api_view(['POST'])
def update_diet_plan(request):
    """
    Update a specific part of an existing diet plan
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Get diet plan ID from request
    diet_plan_id = request.data.get('diet_plan_id')
    if not diet_plan_id:
        return Response({
            'status': 'error',
            'message': 'Diet plan ID is required'
        }, status=400)

    # Get the day and meal type to update
    day = request.data.get('day')
    meal_type = request.data.get('meal_type')
    meal_data = request.data.get('meal_data')

    if not day or not meal_type or not meal_data:
        return Response({
            'status': 'error',
            'message': 'Day, meal_type, and meal_data are required'
        }, status=400)

    try:
        # Find the diet plan
        diet_plan = DietPlan.objects.get(id=diet_plan_id, user=user)

        # Get the current plan data
        current_plan_data = diet_plan.plan_data

        # Check if the day exists in the current plan
        if day not in current_plan_data:
            return Response({
                'status': 'error',
                'message': f'Day "{day}" not found in diet plan'
            }, status=400)

        # Handle raw_plan case (when plan is stored as string in raw_plan field)
        if 'raw_plan' in current_plan_data:
            import json
            try:
                # Try to parse the raw_plan as JSON
                plan_content = json.loads(current_plan_data['raw_plan'])

                # Check if the day exists in the parsed plan
                if day not in plan_content:
                    return Response({
                        'status': 'error',
                        'message': f'Day "{day}" not found in diet plan'
                    }, status=400)

                # Update the specific meal
                if meal_type not in plan_content[day]:
                    return Response({
                        'status': 'error',
                        'message': f'Meal type "{meal_type}" not found for {day}'
                    }, status=400)

                # Update the meal data
                plan_content[day][meal_type] = meal_data

                # Update the raw_plan with modified data
                current_plan_data['raw_plan'] = json.dumps(plan_content)
            except json.JSONDecodeError:
                return Response({
                    'status': 'error',
                    'message': 'Could not parse raw_plan data. It may be in an invalid format.'
                }, status=500)
        else:
            # Regular plan structure (direct JSON)
            if meal_type not in current_plan_data[day]:
                return Response({
                    'status': 'error',
                    'message': f'Meal type "{meal_type}" not found for {day}'
                }, status=400)

            # Update the specific meal
            current_plan_data[day][meal_type] = meal_data

        # Save the updated plan data
        diet_plan.plan_data = current_plan_data
        diet_plan.save()

        # Serialize for response
        serializer = DietPlanSerializer(diet_plan)

        return Response({
            'status': 'success',
            'message': f'Successfully updated {meal_type} for {day}',
            'data': serializer.data
        })
    except DietPlan.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Diet plan not found or you do not have permission to update it'
        }, status=404)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error updating diet plan: {str(e)}'
        }, status=500)


@api_view(['POST'])
def delete_diet_plan(request):
    """
    Delete an existing diet plan
    """
    # Check if the user is authenticated
    token = request.data.get('token')
    if not token:
        return Response({'error': 'Authentication token is required'}, status=401)

    try:
        token_obj = Token.objects.get(token=token)
        if not token_obj.is_valid():
            return Response({'error': 'Token has expired'}, status=401)
        user = token_obj.user
    except Token.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=401)

    # Get diet plan ID from request
    diet_plan_id = request.data.get('diet_plan_id')
    if not diet_plan_id:
        return Response({
            'status': 'error',
            'message': 'Diet plan ID is required'
        }, status=400)

    try:
        # Find the diet plan
        diet_plan = DietPlan.objects.get(id=diet_plan_id, user=user)

        # Delete the plan
        diet_plan.delete()

        return Response({
            'status': 'success',
            'message': 'Diet plan deleted successfully'
        })
    except DietPlan.DoesNotExist:
        return Response({
            'status': 'error',
            'message': 'Diet plan not found or you do not have permission to delete it'
        }, status=404)
    except Exception as e:
        return Response({
            'status': 'error',
            'message': f'Error deleting diet plan: {str(e)}'
        }, status=500)


@api_view(['POST'])
def verify_email_code(request):
    """Verify user's email with verification code"""
    try:
        data = request.data
        email = data.get('email')
        verification_code = data.get('verification_code')

        if not email or not verification_code:
            return Response({
                'status': 'error',
                'message': 'Email and verification code are required'
            }, status=400)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User with this email does not exist'
            }, status=404)

        if user.is_verified:
            return Response({
                'status': 'success',
                'message': 'Email already verified'
            })

        if not user.is_token_valid():
            return Response({
                'status': 'error',
                'message': 'Verification code has expired. Please request a new one.'
            }, status=400)

        if user.verification_code != verification_code:
            return Response({
                'status': 'error',
                'message': 'Invalid verification code'
            }, status=400)

        user.is_verified = True
        user.verification_token = None
        user.verification_token_created_at = None
        user.verification_code = None
        user.save()

        return Response({
            'status': 'success',
            'message': 'Email verified successfully'
        })

    except Exception as e:
        return Response({
            'status': 'error',
            'message': str(e)
        }, status=500)


@api_view(['POST'])
def concise_health_answer(request):
    try:
        # Get user token and validate
        token = request.data.get('token')
        if not token:
            return Response({'error': 'Authentication token is required'}, status=401)

        # Validate token
        token_obj = Token.objects.filter(token=token).first()
        if not token_obj or not token_obj.is_valid():
            return Response({'error': 'Invalid or expired token'}, status=401)

        user = token_obj.user

        # Get question from request
        question = request.data.get('question')
        if not question:
            return Response({'error': 'Question is required'}, status=400)

        # Get user profile and metrics data for context
        user_profile = {
            'age': user.age,
            'gender': user.gender,
            'height': user.height,
            'weight': user.weight,
            'fitness_goal': user.fitness_goal,
            'activity_level': user.activity_level,
            'diet_preference': user.diet_preference
        }

        metrics = FitnessMetrics.objects.filter(
            user=user).order_by('-date').first()
        metrics_data = {}
        if metrics:
            metrics_data = {
                'heart_rate': metrics.heart_rate,
                'steps': metrics.steps,
                'calories': metrics.calories,
                'sleep_hours': metrics.sleep_hours
            }

        # Get concise answer
        answer = get_concise_health_answer(
            question, user_profile, metrics_data)

        # Save the Q&A to history
        HealthQA.objects.create(
            user=user,
            question=question,
            answer=answer
        )

        return Response({
            'question': question,
            'answer': answer
        })

    except Exception as e:
        return Response({'error': str(e)}, status=500)


def get_concise_health_answer(question, user_profile, metrics_data):
    # Format the prompt to ensure a 3-sentence response
    prompt = f"""
    You are a health and fitness expert. Answer the following health, exercise, or medical question in EXACTLY 3 sentences - no more, no less.
    Make your answer informative, accurate, and concise.
    
    User profile: {user_profile}
    Recent metrics: {metrics_data}
    
    Question: {question}
    
    Your 3-sentence answer:
    """

    try:
        # Import OpenAI client and load API key from environment
        from openai import OpenAI
        import os

        client = OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))

        # Use the correct client API format
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a health and fitness expert. You always respond with exactly 3 sentences."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.7
        )

        # Extract the content using the correct response format
        answer = response.choices[0].message.content.strip()

        # Ensure we have exactly 3 sentences
        sentences = answer.split('.')
        valid_sentences = [s.strip() + '.' for s in sentences if s.strip()]

        if len(valid_sentences) > 3:
            return ''.join(valid_sentences[:3])
        elif len(valid_sentences) < 3:
            # This shouldn't happen with proper prompting, but just in case
            return answer + ' This completes your three-sentence answer.'
        else:
            return ''.join(valid_sentences)

    except Exception as e:
        # Include more detailed error information for debugging
        import traceback
        print(f"OpenAI API Error: {str(e)}")
        print(traceback.format_exc())
        return f"Sorry, I couldn't generate an answer at this time. Please try again later. This is a technical issue that will be resolved soon."


@api_view(['POST'])
def set_food_culture(request):
    # Extract the token from the request body
    token_string = request.data.get('token')
    if not token_string:
        return JsonResponse({'error': 'Authentication token is required'}, status=400)

    # Validate the token
    try:
        token = Token.objects.get(token=token_string)
        if not token.is_valid():
            return JsonResponse({'error': 'Token has expired'}, status=401)
        user = token.user
    except Token.DoesNotExist:
        return JsonResponse({'error': 'Invalid token'}, status=401)

    # Check if the user has already set their food culture
    if user.food_culture is not None and user.food_culture != '':
        return JsonResponse({'error': 'Food culture has already been set'}, status=400)

    # Get the food culture from the request
    food_culture = request.data.get('food_culture')
    if not food_culture:
        return JsonResponse({'error': 'Food culture is required'}, status=400)

    # Update the user's food culture
    user.food_culture = food_culture
    user.save()

    return JsonResponse({'success': True, 'message': 'Food culture set successfully'})
