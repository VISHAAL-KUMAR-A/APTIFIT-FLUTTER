from django.urls import path
from . import views

urlpatterns = [
    path('api/register', views.register_user, name='register_user'),
    path('api/login', views.login_user, name='login_user'),
    path('api/validate-token', views.validate_token, name='validate_token'),
    path('api/logout', views.logout_user, name='logout_user'),
    path('api/verify-email/<str:token>',
         views.verify_email, name='verify_email'),
    path('api/resend-verification', views.resend_verification,
         name='resend_verification'),
    path('api/forgot-password', views.forgot_password, name='forgot_password'),
    path('api/reset-password/<str:token>',
         views.reset_password, name='reset_password'),
    path('api/update-name', views.update_user_name, name='update_user_name'),
    path('api/update-age', views.update_user_age, name='update_user_age'),
    path('api/update-gender', views.update_user_gender, name='update_user_gender'),
    path('api/update-height', views.update_user_height, name='update_user_height'),
    path('api/update-weight', views.update_user_weight, name='update_user_weight'),
]
