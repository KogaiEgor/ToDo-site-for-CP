from django.urls import path
from todo.registration import views
from rest_framework.urlpatterns import format_suffix_patterns

urlpatterns = [
    path('signup/', views.RegisterView.as_view(), name='signupuser'),
    path('login/', views.LogInUser.as_view(), name='loginuser'),
    path('logout/', views.LogOutUser.as_view(), name='logoutuser'),
    path('personalaccount', views.PersonalAccount.as_view(), name='personalaccount'),
    path('personalaccount/changepassword', views.ChangePasswordView.as_view(), name='changepassword'),
]

urlpatterns = format_suffix_patterns(urlpatterns)