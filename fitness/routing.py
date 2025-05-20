from django.urls import path
from fitness.consumers import ChatConsumer, FriendRequestConsumer

websocket_urlpatterns = [
    path("chat/", ChatConsumer.as_asgi()),
    path("friends/<int:user_id>/", FriendRequestConsumer.as_asgi()),
]
