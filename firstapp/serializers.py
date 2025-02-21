# serializers.py
from rest_framework import serializers
from .models import JobPost, UserProfile

class JobPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobPost
        fields = '__all__'

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['id', 'username', 'email', 'full_name', 'education','experience','bio','tags']
        
class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)
    class Meta:
        model = UserProfile
        fields = ['id', 'username', 'email', 'password']
        


