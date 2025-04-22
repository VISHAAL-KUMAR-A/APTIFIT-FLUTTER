from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status
from .models import User, Token
from .serializers import UserSerializer
from django.contrib.auth.hashers import make_password, check_password
import uuid
from datetime import timedelta
from django.utils import timezone
from .utils import send_verification_email, send_password_reset_email
import os
import openai
from django.conf import settings


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
