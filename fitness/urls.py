from django.urls import path
from . import views

urlpatterns = [
    path('api/user', views.get_user_data, name='get_user_data'),
]
