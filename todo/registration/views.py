from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.db.models.functions import TruncDay, TruncDate
from rest_framework.response import Response
from .serializers import RegisterSerializer, LoginSerializer, ChangePasswordSerializer
from rest_framework import generics, permissions
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from todo.models import Todo
from django.utils import timezone
from datetime import timedelta, datetime
from django.db.models import Count

class RegisterView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer
    def get(self, request, *args,  **kwargs):
        return render(request, 'todo/signupuser.html', {'form': UserCreationForm()})
    def post(self, request, *args,  **kwargs):
        serializer = self.get_serializer(data=request.data)
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
                                                            'error': 'Неправильно введен пароль'})


class LogOutUser(APIView):
    permission_classes = [permissions.IsAuthenticated]
    def post(self, request, *args, **kwargs):
        logout(request)
        return redirect('home')

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
        user = request.user.get_username()
        return self.chart(request)

    def chart(self, request):
        data = []

        labels = []
        some_day_last_week = datetime.now().date() - timedelta(days=7)

        qs = Todo.objects.filter(
            user=request.user,
            datecompleted__isnull=False,
            datecompleted__gte=some_day_last_week,
        )
        qs = qs.values("datecompleted").annotate(
            day=TruncDay('datecompleted'),
        ).values('day').annotate(
            created_count=Count('day')
        )
        weekdays = {'Sunday': 'Воскресенье', 'Monday': 'Понедельник', 'Tuesday': 'Вторник', 'Wednesday': 'Среда',
                    'Thursday': 'Четверг', 'Friday': 'Пятница', 'Saturday': 'Суббота'}
        temp_labels = list(weekdays)
        for todo in qs:
            data.append(todo['created_count'])
            labels.append(todo['day'].strftime("%A"))
        temp_labels = temp_labels[temp_labels.index(datetime.today().strftime('%A')) + 1:] + \
                      temp_labels[0:temp_labels.index(datetime.today().strftime('%A')) + 1]
        for i in range(7):
            if temp_labels[i] not in labels:
                labels.insert(i, temp_labels[i])
                data.insert(i, 0)
        for i in range(len(labels)):
            labels[i] = weekdays[labels[i]]


        return render(request, 'todo/personalaccount.html',
                      {'labels': labels,
                        'data': data })

