# Generated by Django 5.2 on 2025-05-12 08:53

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fitness', '0033_message'),
    ]

    operations = [
        migrations.AddField(
            model_name='token',
            name='last_activity',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
