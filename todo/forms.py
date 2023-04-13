from .models import Todo
from django.forms import ModelForm
from django import forms

class TodoForm(ModelForm):
    class Meta:
        model = Todo
        fields =  ['title', 'memo', 'important', 'iscompleted']

