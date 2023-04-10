from django.db import models
from django.contrib.auth.models import User
class Todo(models.Model):
    title = models.CharField(max_length=100)
    memo = models.TextField(blank=True)
    created = models.DateTimeField(auto_now_add=True)
    datecompleted = models.DateTimeField(null=True, blank=True)
    important = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    iscompleted = models.BooleanField(default=False)
    deadline = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title

class Product(models.Model):
    category = models.CharField(max_length=100, null=False, blank=False)

    def __str__(self):
        return f'{self.category}'