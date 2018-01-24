# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect
from django.contrib import messages
from models import *
import bcrypt, re

# Create your views here.
def index(request):
    try:
        user_level_access = Access.objects.filter(level="User")[0]
    except:
        Access.objects.create(level="User")
        Access.objects.create(level="Admin")
    return render(request, 'wall_app/index.html')

def dashboard(request):
    if 'user' in request.session:
        user = User.objects.get(id=request.session['user'])
        if user.user_level.level == "Admin":
            return redirect('/dashboard/admin')
    context = {
        'users': User.objects.all()
    }
    return render(request, 'wall_app/dashboard.html', context)

def dashboard_admin(request):
    if 'user' in request.session:
        user = User.objects.get(id=request.session['user'])
        if user.user_level.level == "Admin":
            context = {
                'users': User.objects.all()
            }
            return render(request, 'wall_app/dashboard_admin.html', context)
    return redirect('/dashboard')

def register(request):
    return render(request, "wall_app/register.html")

def process_reg(request):
    if request.method == "POST":
        errors = User.objects.basic_validator(request.POST)
        if len(errors):
            for tag, error in errors.iteritems():
                messages.error(request, error, extra_tags=tag)
            return redirect('/register')
        else:
            print 'Else statement in process_reg views.py'
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            email = request.POST['email']
            password = request.POST['password']
            hashed_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            user_level_access = Access.objects.filter(level="User")[0]
            User.objects.create(first_name=first_name, last_name=last_name, email=email, password=hashed_pass, user_level=user_level_access)
            request.session['user'] = User.objects.filter(email=email)[0].id
    return redirect('/dashboard')

def login(request):
    return render(request, 'wall_app/login.html')

def process_log(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        try:
            user = User.objects.get(email=email)
        except:
            messages.error(request, "Your email isn't registered")
            return redirect('/login')
        hashed_pw = user.password
        if bcrypt.checkpw(password.encode(), hashed_pw.encode()):
            request.session['user'] = user.id
            return redirect('/dashboard')
        else:
            messages.error(request, "Wrong password")
            return redirect('/login')
    return redirect('/login')

def logout(request):
    request.session.clear()
    return redirect('/')

def users_show_id(request, number):
    try:
        user = User.objects.get(id=number)
    except:
        return redirect('/dashboard')
    messages = Message.objects.filter(receiver=user)
    comments = []
    #This is the thing you need to ask Alan or Graham about
    for message in messages:
        try:
            comments.append(Comment.objects.filter(message=message))
        except:
            pass
    context = {
        'user': user,
        'messages': messages,
        'comments': comments
    }
    #This is the end of the thing you need to ask Alan or Graham about
    return render(request, 'wall_app/users_show_id.html', context)

def process_msg(request):
    if request.method == 'POST':
        target_string = "/users/show/" + str(request.POST['user_id'])
        receiver = User.objects.get(id=request.POST['user_id'])
        poster = User.objects.get(id=request.session['user'])
        message = request.POST['message']
        if message == '':
            return redirect(target_string)
        Message.objects.create(message=message, receiver=receiver, poster=poster)
        return redirect(target_string)
    return redirect('/')

def process_cmt(request):
    if request.method == 'POST':
        message = Message.objects.get(id=request.POST['message_id'])
        comment = request.POST['comment']
        poster = User.objects.get(id=request.session['user'])
        Comment.objects.create(comment=comment, message=message, poster=poster)
        target_string = '/users/show/' + str(message.receiver.id)
        return redirect(target_string)
    return redirect('/')

def users_edit_id(request, number):
    if 'user' in request.session:
        print "request.session['user']: " + str(request.session['user'])
        print "number: " + str(number)
        if int(request.session['user']) == int(number):
            user = User.objects.get(id=request.session['user'])
            context = {
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email
            }
            return render(request, 'wall_app/users_edit_id.html', context)
    return redirect('/dashboard')

def process_edit_info(request):
    if request.method == "POST":
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        errors = {}
        if len(request.POST['first_name']) < 2:
            errors['first_name'] = "First Name must be 2 characters or longer"
        if len(request.POST['last_name']) < 2:
            errors['last_name'] = "Last name must be 2 characters or longer"
        if not EMAIL_REGEX.match(request.POST['email']):
            errors['email'] = "Email must be valid"
        user = User.objects.get(id=request.session['user'])
        if not user.email == request.POST['email']:
            try:
                User.objects.get(email=request.POST['email'])
                errors['email'] = "That email is already in use"
            except:
                pass
        if len(errors):
            for tag, error in errors.iteritems():
                messages.error(request, error, extra_tags=tag)
            target_string = "/users/edit/" + str(request.session['user'])
            return redirect(target_string)
        else:
            user = User.objects.get(id=request.session['user'])
            user.first_name = request.POST['first_name']
            user.last_name = request.POST['last_name']
            user.email = request.POST['email']
            user.save()
            target_string = "/users/show/" + str(user.id)
            return redirect(target_string)
    return redirect('/dashboard')

def process_pw_change(request):
    if request.method == "POST":
        errors = {}
        if len(request.POST['password']) < 8:
            errors['password'] = 'Password must be 8 or more characters'
        if request.POST['password'] != request.POST['r_password']:
            errors['r_password'] = 'Password fields must match'
        if len(errors):
            for tag, error in errors.iteritems():
                messages.error(request, error, extra_tags=tag)
            target_string = "/users/edit/" + str(request.session['user'])
            return redirect(target_string)
        else:
            password = request.POST['password']
            hashed_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            user = User.objects.get(id=request.session['user'])
            user.password = hashed_pass
            user.save()
            target_string = '/users/show/' + str(user.id)
            return redirect(target_string)
    return redirect('/dashboard')

def process_desc_change(request):
    if request.method == "POST":
        pass
    return redirect('/dashboard')

def users_new(request):
    if 'user' in request.session:
        user = User.objects.get(id=request.session['user'])
        if user.user_level.level == "Admin":
            return render(request, 'wall_app/users_new.html')
    return redirect('/dashboard')

def process_users_new(request):
    if request.method == "POST":
        errors = User.objects.basic_validator(request.POST)
        if len(errors):
            for tag, error in errors.iteritems():
                messages.error(request, error, extra_tags=tag)
            return redirect('/users/new')
        else:
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            email = request.POST['email']
            password = request.POST['password']
            hashed_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            user_level_access = Access.objects.filter(level="User")[0]
            User.objects.create(first_name=first_name, last_name=last_name, email=email, password=hashed_pass, user_level=user_level_access)
            request.session['user'] = User.objects.filter(email=email)[0].id
    return redirect('/dashboard')

def admin_edit_id(request, number):
    if 'user' in request.session:
        user = User.objects.get(id=request.session['user'])
        if user.user_level.level == "Admin":
            user = User.objects.get(id=number)
            context = {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'user_level': user.user_level.level
            }
            return render(request, 'wall_app/admin_edit_id.html', context)
    return redirect('/dashboard')
def process_admin_edit_info(request):
    if request.method == "POST":
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        errors = {}
        if len(request.POST['first_name']) < 2:
            errors['first_name'] = "First Name must be 2 characters or longer"
        if len(request.POST['last_name']) < 2:
            errors['last_name'] = "Last name must be 2 characters or longer"
        if not EMAIL_REGEX.match(request.POST['email']):
            errors['email'] = "Email must be valid"
        user_emailcheck = User.objects.get(id=request.POST['id'])
        if not user_emailcheck.email == request.POST['email']:
            try:
                User.objects.get(email=request.POST['email'])
                errors['email'] = "That email is already in use"
            except:
                pass
        if len(errors):
            for tag, error in errors.iteritems():
                messages.error(request, error, extra_tags=tag)
            target_string = "/admin/edit/" + str(request.POST['id'])
            return redirect(target_string)
        else:
            user = User.objects.get(id=request.POST['id'])
            user.first_name = request.POST['first_name']
            user.last_name = request.POST['last_name']
            user.email = request.POST['email']
            user_level = Access.objects.get(id=request.POST['user_level'])
            user.user_level = user_level
            user.save()
            target_string = "/users/show/" + str(user.id)
            return redirect(target_string)
    return redirect('/dashboard')

def admin_destroy_id(request, number):
    if 'user' in request.session:
        user = User.objects.get(id=request.session['user'])
        if user.user_level.level == "Admin":
            user = User.objects.get(id=number)
            context = {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'user_level': user.user_level.level
            }
            return render(request, 'wall_app/admin_destroy_id.html', context)
    return redirect('/dashboard')

def process_admin_destroy(request):
    if request.method == "POST":
        if 'user' in request.session:
            admin_user = User.objects.get(id=request.session['user'])
            if admin_user.user_level.level == "Admin":
                user = User.objects.get(id=request.POST['id'])
                user.delete()
    return redirect('/dashboard')
