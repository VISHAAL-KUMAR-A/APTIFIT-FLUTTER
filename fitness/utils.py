from django.core.mail import send_mail
from django.conf import settings
from django.urls import reverse


def send_verification_email(user, request):
    """Send an email verification to the user"""
    token = user.generate_verification_token()
    verification_url = request.build_absolute_uri(
        reverse('verify_email', kwargs={'token': token})
    )

    subject = 'Verify your email address'
    message = f'Click the link below to verify your email:\n\n{verification_url}\n\nThe link is valid for 24 hours.'

    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )


def send_password_reset_email(user, request):
    """Send a password reset email to the user"""
    token = user.generate_reset_password_token()
    reset_url = request.build_absolute_uri(
        reverse('reset_password', kwargs={'token': token})
    )

    subject = 'Reset your password'
    message = f'Click the link below to reset your password:\n\n{reset_url}\n\nThe link is valid for 1 hour.'

    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
