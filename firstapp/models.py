from django.db import models
from django.contrib.auth.models import AbstractUser

class UserProfile(AbstractUser):  
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)
    full_name = models.CharField(max_length=150,blank=True, null=True)
    education = models.TextField(blank=True, null=True) 
    bio = models.TextField(blank=True, null=True)
    experience = models.TextField(blank=True, null=True) 
    tags = models.TextField(blank=True, null=True)
    resume = models.URLField(blank=True, null=True)
    def __str__(self):
        return self.username


class JobPost(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='job_posts')
    job_title = models.CharField(max_length=200)
    company_name = models.CharField(max_length=150)
    country = models.CharField(max_length=100)
    industry = models.CharField(max_length=100)
    job_function = models.CharField(max_length=100)
    experience_level = models.CharField(max_length=100)
    location = models.CharField(max_length=150)
    details = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True) 
    tags = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.job_title