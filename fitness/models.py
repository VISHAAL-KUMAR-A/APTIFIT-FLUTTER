from django.db import models

# Create your models here.


class User(models.Model):
    email = models.EmailField(max_length=200, unique=True)
    password = models.CharField(max_length=200)
    # Optional fields that can be null/blank
    name = models.CharField(max_length=200, null=True, blank=True)
    age = models.IntegerField(null=True, blank=True)
    gender = models.CharField(max_length=200, null=True, blank=True)
    height = models.IntegerField(null=True, blank=True)
    weight = models.IntegerField(null=True, blank=True)
