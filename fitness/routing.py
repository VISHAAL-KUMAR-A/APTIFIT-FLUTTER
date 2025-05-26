from django.urls import path
from fitness.consumers import ChatConsumer, FriendRequestConsumer, ChatNotificationConsumer

websocket_urlpatterns = [
    path("chat/", ChatConsumer.as_asgi()),
    path("friends/<int:user_id>/", FriendRequestConsumer.as_asgi()),
    path("chat-notifications/<int:user_id>/",
         ChatNotificationConsumer.as_asgi()),
]
