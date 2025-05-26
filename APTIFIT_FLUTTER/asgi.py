"""
ASGI config for APTIFIT_FLUTTER project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

import os
import django
from django.core.asgi import get_asgi_application

# Set Django settings module FIRST
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'APTIFIT_FLUTTER.settings')

# Setup Django BEFORE importing any Django models or apps
django.setup()

# Now import Django ASGI application
django_asgi_app = get_asgi_application()

# Delayed import to avoid AppRegistryNotReady


def get_application():
    from channels.routing import ProtocolTypeRouter, URLRouter
    from channels.auth import AuthMiddlewareStack
    from fitness import routing

    return ProtocolTypeRouter({
        "http": django_asgi_app,
        "websocket": AuthMiddlewareStack(
            URLRouter(
                routing.websocket_urlpatterns
            )
        ),
    })


application = get_application()
