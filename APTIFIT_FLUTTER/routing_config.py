from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from fitness import routing


def get_asgi_application():
    return ProtocolTypeRouter({
        "http": get_django_asgi_application(),
        "websocket": AuthMiddlewareStack(
            URLRouter(
                routing.websocket_urlpatterns
            )
        ),
    })


def get_django_asgi_application():
    from django.core.asgi import get_asgi_application
    return get_asgi_application()
