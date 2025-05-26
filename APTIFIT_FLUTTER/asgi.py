"""
ASGI config for APTIFIT_FLUTTER project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/asgi/
"""

from APTIFIT_FLUTTER.routing_config import get_asgi_application
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'APTIFIT_FLUTTER.settings')
django.setup()

application = get_asgi_application()
