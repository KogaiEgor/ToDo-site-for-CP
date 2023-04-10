from .models import Todo
from django.forms import ModelForm
from django import forms
from .models import Product

class TodoForm(ModelForm):
    class Meta:
        model = Todo
        fields =  ['title', 'memo', 'important', 'iscompleted']

class ProductForm(ModelForm):
    class Meta:
        model = Product
        fields = '__all__'
        widgets = {
            'category': forms.TextInput(attrs={'class': 'form-control'}),
        }
