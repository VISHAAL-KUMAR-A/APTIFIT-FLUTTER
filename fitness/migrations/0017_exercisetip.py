# Generated by Django 5.2 on 2025-04-24 12:06

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('fitness', '0016_exerciseplan'),
    ]

    operations = [
        migrations.CreateModel(
            name='ExerciseTip',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('tip_content', models.CharField(max_length=200)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('exercise_plan', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='tips', to='fitness.exerciseplan')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='exercise_tips', to='fitness.user')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
