# isort: skip_file
"""
ASGI config for APTIFIT_FLUTTER project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""
from fitness import routing
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
import os
import django
from django.core.asgi import get_asgi_application

# Set Django settings module FIRST
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'APTIFIT_FLUTTER.settings')

# Setup Django BEFORE importing any Django models or apps
django.setup()

# Now import Django ASGI application
django_asgi_app = get_asgi_application()

# Import ALL Django app components AFTER django.setup()
# Create the ASGI application
application = ProtocolTypeRouter({
    "http": django_asgi_app,
    "websocket": AuthMiddlewareStack(
        URLRouter(
            routing.websocket_urlpatterns
        )
    ),
})
