from django.contrib import admin
from django.urls import path, include
from todo import views

urlpatterns = [
    path('admin/', admin.site.urls),

    #Аутентификация
    path('', include('todo.registration.urls')),

    #Список дел
    path('', views.home, name='home'),
    path('current/', views.CurrentToDo, name='CurrentToDo'),
    path('completed/', views.completedtodos, name='completedtodos'),
    path('create/', views.CreateToDo, name='CreateToDo'),
    path('todo/<int:todo_pk>', views.viewtodo, name='viewtodo'),
    path('todo/<int:todo_pk>/complete', views.completetodo, name='completetodo'),
    path('todo/<int:todo_pk>/delete', views.deletetodo, name='deletetodo'),

]

