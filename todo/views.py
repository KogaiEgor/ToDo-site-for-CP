from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login, logout, authenticate

#superusers name - red_ranger
#password - o711begor

def home(request):
    return render(request, 'todo/home.html')
def signupuser(request):
    if request.method == "GET":
        return render(request, 'todo/signupuser.html', {'form': UserCreationForm()})
    else:
        if request.POST['password1'] == request.POST['password2']:
            try:
                user = User.objects.create_user(request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('CurrentToDo')
            except IntegrityError:
                return render(request, 'todo/signupuser.html',
                              {'form': UserCreationForm(), 'error': 'Это имя пользователя уже используется'})
        else:
            return render(request, 'todo/signupuser.html', {'form': UserCreationForm(), 'error':'Пароли не совпадают'})

def logoutuser(request):
    if request.method == "POST":
        logout(request)
        return redirect('home')

def loginuser(request):
    if request.method == "GET":
        return render(request, 'todo/loginuser.html', {'form': AuthenticationForm()})
    else:
        user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'todo/loginuser.html', {'form': AuthenticationForm(), 'error': 'Неправильный логин или пароль'})
        else:
            login(request, user)
            return redirect('CurrentToDo')
def CurrentToDo(request):
    return render(request, 'todo/CurrentToDo.html')
