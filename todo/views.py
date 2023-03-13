import http

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.contrib.auth import login, logout, authenticate
from .forms import TodoForm
from .models import Todo
from django.utils  import timezone
from django.contrib.auth.decorators import login_required
from rest_framework.response import Response
from .serializers import RegisterSerializer, UserSerializer, LoginSerializer, ChangePasswordSerializer
from rest_framework import generics, permissions
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.http import HttpResponseBadRequest
#superusers name - red_ranger
#password - o711begor

def home(request):
    return render(request, 'todo/home.html')
"""def signupuser(request):
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
            return render(request, 'todo/signupuser.html', {'form': UserCreationForm(), 'error':'Пароли не совпадают'})"""

class RegisterView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer
    def get(self, request, *args,  **kwargs):
        return render(request, 'todo/signupuser.html', {'form': UserCreationForm()})
    def post(self, request, *args,  **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
        except:
            return render(request, 'todo/signupuser.html', {'form': UserCreationForm(), 'error': 'Пароли не совпадают'})
        try:
            if serializer.is_valid(raise_exception=False):
                user = serializer.save()
                login(request, user)
                return redirect('CurrentToDo')
            else:
                return render(request, 'todo/signupuser.html',
                              {'form': UserCreationForm(), 'error': 'Это имя пользователя уже используется'})
        except:
            return render(request, 'todo/signupuser.html', {'form': UserCreationForm(),
                                                            'error': 'Пароль должен быть не короче 6 символов'})
"""
@login_required
def logoutuser(request):
    if request.method == "POST":
        logout(request)
        return redirect('home')
"""
class LogOutUser(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request, *args, **kwargs):
        logout(request)
        return redirect('home')

@login_required
def CreateToDo(request):
    if request.method == "GET":
        return render(request, 'todo/CreateToDo.html', {'form': TodoForm()})
    else:
        try:
            form = TodoForm(request.POST)
            newtodo = form.save(commit=False)
            newtodo.user = request.user
            newtodo.save()
            return redirect('CurrentToDo')
        except ValueError:
            return render(request, 'todo/CreateToDo.html', {'form': TodoForm(), 'error': 'Введены неверные данные'})
"""
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

"""
class LogInUser(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = LoginSerializer
    def get(self, request, *args, **kwargs):
        return render(request, 'todo/loginuser.html', {'form': AuthenticationForm()})
    def post(self, request, *args,  **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                user = serializer.save()
                login(request, user)
                return redirect('CurrentToDo')
        except:
            return render(request, 'todo/loginuser.html',
                          {'form': AuthenticationForm(), 'error': 'Неправильный логин или пароль'})


@login_required
def CurrentToDo(request):
    todos = Todo.objects.filter(user=request.user, datecompleted__isnull=True)
    return render(request, 'todo/CurrentToDo.html', {'todos':todos})
@login_required
def completedtodos(request):
    todos = Todo.objects.filter(user=request.user, datecompleted__isnull=False).order_by('-datecompleted')
    return render(request, 'todo/completedtodos.html', {'todos': todos})
@login_required
def viewtodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'GET':
        form = TodoForm(instance=todo)
        return render(request, 'todo/viewtodo.html', {'todo': todo, 'form': form})
    else:
        try:
            form = TodoForm(request.POST, instance=todo)
            form.save()
            return redirect('CurrentToDo')
        except ValueError:
            return render(request, 'todo/viewtodo.html', {'todo': todo, 'form': form, 'error': 'Некоректный ввод данных'})

@login_required
def completetodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.datecompleted = timezone.now()
        todo.save()
        return redirect('CurrentToDo')
@login_required
def deletetodo(request, todo_pk):
    todo = get_object_or_404(Todo, pk=todo_pk, user=request.user)
    if request.method == 'POST':
        todo.delete()
        return redirect('CurrentToDo')

class ChangePasswordView(generics.UpdateAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        return render(request, 'todo/changepassword.html')

    def post(self, request, *args, **kwargs):
        if self.update(request):
            return redirect('CurrentToDo')
        return render(request, 'todo/changepassword.html', {'error': 'неправильный пароль'})

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return False
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PersonalAccount(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return render(request, 'todo/personalaccount.html')
