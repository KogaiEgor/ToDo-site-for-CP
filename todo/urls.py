from django.urls import path
from todo import views
from rest_framework.urlpatterns import format_suffix_patterns

urlpatterns = [
    path('signup/', views.RegisterView.as_view(), name='signupuser'),
    path('login/', views.LogInUser.as_view(), name='loginuser'),
    path('logout/', views.LogOutUser.as_view(), name='logoutuser'),
]

urlpatterns = format_suffix_patterns(urlpatterns)
