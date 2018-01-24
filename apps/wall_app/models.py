# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
import re

# Create your models here.
class Access(models.Model):
    level = models.CharField(max_length=255)

class UserManager(models.Manager):
    def basic_validator(self, postData):
        errors = {}
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        query_set = User.objects.filter(email=postData['email'])
        if len(postData['first_name']) < 2:
            errors['first_name'] = "First name must be longer than two characters"    
        if len(postData['last_name']) < 2:
            errors['last_name'] = "Last name must be longer than two characters"
        if len(postData['email']) < 1:
            errors['email'] = "Email field cannot be blank"
        elif not EMAIL_REGEX.match(postData['email']):
            errors['email'] = "Email must be valid"
        elif len(query_set) > 0:
            errors['email'] = "Email already in database"
        if len(postData['password']) < 8:
            errors['password'] = "Password must be 8 or more characters"
        elif postData['password'] != postData['r_password']:
            errors['password'] = "Password fields must match"
        return errors
        
class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    user_level = models.ForeignKey(Access, related_name="users")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class Message(models.Model):
    message = models.CharField(max_length=255)
    receiver = models.ForeignKey(User, related_name="received_messages")
    poster = models.ForeignKey(User, related_name="posted_messages")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class Comment(models.Model):
    comment = models.CharField(max_length=255)
    message = models.ForeignKey(Message, related_name="comments")
    poster = models.ForeignKey(User, related_name="comments")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
