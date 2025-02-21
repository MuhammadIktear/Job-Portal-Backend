from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from . import views

urlpatterns = [
    path('api/register/', views.UserRegistrationView.as_view(), name='register'),
    path('api/login/', views.UserLoginView.as_view(), name='login'),
    path('api/logout/', views.UserLogoutView.as_view(), name='logout'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/user_profile/<int:pk>/', views.UserProfileDetail.as_view(), name='user_profile'),
    path('api/job_posts/', views.job_post_list, name='job_post-list'),
    path('api/job_posts/<int:pk>/', views.job_post_detail, name='job_post-detail'),
    path('api/suggest_jobs/', views.suggest_jobs, name='suggest_jobs'), 
    path('api/extract_tags/', views.extract_tags, name='extract_tags'),
    path('api/get_advice_from_tags/', views.get_advice_from_tags, name='get_advice_from_tags'),
    path('api/verify-email/<str:uidb64>/<str:token>/', views.EmailVerificationView.as_view(), name='verify-email'),
    path('chatbot/', views.chatbot_endpoint, name='chatbot_endpoint'),
]
