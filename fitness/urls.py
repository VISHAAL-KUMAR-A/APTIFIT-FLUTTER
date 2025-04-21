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
]
