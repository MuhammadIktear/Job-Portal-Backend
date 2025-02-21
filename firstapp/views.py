from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from .models import JobPost, UserProfile
from .serializers import JobPostSerializer, UserProfileSerializer, UserRegisterSerializer
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
import requests
import json
import os
import fitz 
import io
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.shortcuts import redirect

import logging

logger = logging.getLogger(__name__)
from django.contrib.auth import get_user_model
User = get_user_model()

class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    permission_classes = [permissions.AllowAny]
    def perform_create(self, serializer):
        user = serializer.save()
        password = self.request.data.get('password')
        user.set_password(password)
        user.is_active = False 
        self.send_verification_email(user)
        user.save()

    def send_verification_email(self, user):
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verification_link = f"http://127.0.0.1:8000/api/verify-email/{uid}/{token}/"
        send_mail(
            subject="Verify Your Email Address",
            message=f"Please click the following link to verify your email: {verification_link}",
            from_email="iktear500@gmail.com",  
            recipient_list=[user.email],
            fail_silently=False,
        )

class EmailVerificationView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = UserProfile.objects.get(pk=uid) 
            if user and default_token_generator.check_token(user, token):
                user.is_active = True  
                user.save()
                return redirect('http://127.0.0.1:5500/login.html') 
            else:
                return Response({'error': 'Invalid or expired token'}, status=status.HTTP_400_BAD_REQUEST)
        except (TypeError, ValueError, OverflowError, UserProfile.DoesNotExist) as e:
            return Response({'error': 'Invalid token or user not found'}, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            if not user.is_active:
                return Response({'error': 'Please verify your email before logging in'}, status=status.HTTP_403_FORBIDDEN)

            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': UserProfileSerializer(user).data
            }, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class UserLogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data.get("refresh_token")
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

class UserProfileDetail(generics.RetrieveUpdateAPIView):
    queryset = UserProfile.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.AllowAny]
    
def extract_text_from_pdf(pdf_file):
    try:
        pdf_bytes = pdf_file.read()
        pdf_stream = io.BytesIO(pdf_bytes)
        doc = fitz.open(None, pdf_stream, filetype="pdf")
        text = ""
        for page in doc:
            text += page.get_text()
        return text
    except Exception as e:
        logger.exception(f"Error extracting text: {e}") 
        return None
    
@api_view(['POST'])
def extract_tags(request):
    if 'resume' not in request.FILES:
        return Response({'error': 'No resume file provided.'}, status=status.HTTP_400_BAD_REQUEST)
    resume_file = request.FILES['resume']
    id = request.data.get('id')
    if not id:
        return Response({'error': 'User ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        extracted_text = extract_text_from_pdf(resume_file)
        if not extracted_text:
            return Response({'error': 'Failed to extract text from PDF.'}, status=status.HTTP_400_BAD_REQUEST)
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "google/gemini-flash-1.5", 
            "messages": [{"role": "user", "content": f"Create a comma-separated list of relevant skills for this resume. These skills help to find the expected job for a job recommendation system. :\n\n{extracted_text}"}]
        }
        print("Request Payload:", payload) 
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=payload
        )
        print("Response Status Code:", response.status_code) 
        print("Response Text:", response.text)
        response.raise_for_status()
        extracted_tags_json = response.json()
        extracted_tags_text = extracted_tags_json.get('choices', [{}])[0].get('message', {}).get('content', '')
        tags = [tag.strip().lower() for tag in extracted_tags_text.split(",")]
        try:
            user_profile, created = UserProfile.objects.get_or_create(id=id)
            user_profile.tags = ", ".join(tags)
            user_profile.save()
        except Exception as e:
            logger.exception(f"Error saving tags to UserProfile: {e}")
            return Response({'error': 'Error saving tags to database.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response({'tags': tags}, status=status.HTTP_200_OK)

    except requests.exceptions.RequestException as e:
        logger.exception(f"Error with OpenRouter API: {e}")
        return Response({'error': 'Error with OpenRouter API.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    except Exception as e:
        logger.exception(f"Unexpected error in extract_tags: {e}")
        return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def recommend_jobs(candidate_skills, job_posts):
    candidate_skills_list = [skill.strip().lower() for skill in candidate_skills.split(',')] if candidate_skills else []

    all_skills = [candidate_skills] 

    for post in job_posts:
        if post.tags:
            all_skills.append(post.tags)
    vectorizer = CountVectorizer()
    vectors = vectorizer.fit_transform(all_skills)
    similarities = cosine_similarity(vectors[0:1], vectors[1:])

    ranked_jobs = []
    for i, score in enumerate(similarities[0]):
        ranked_jobs.append((job_posts[i], score))

    ranked_jobs.sort(key=lambda x: x[1], reverse=True) 
    recommended_jobs = [job for job, score in ranked_jobs]
    return recommended_jobs


@api_view(['POST'])
def suggest_jobs(request):
    candidate_id = request.data.get('candidate_id')

    if not candidate_id:
        return Response({'error': 'Candidate ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        candidate_profile = UserProfile.objects.get(pk=candidate_id)
    except UserProfile.DoesNotExist:
        return Response({'error': 'Candidate profile not found.'}, status=status.HTTP_404_NOT_FOUND)

    try:
        candidate_skills = candidate_profile.tags
    except UserProfile.DoesNotExist:
        return Response({'error': 'User profile extra not found for this user.'}, status=status.HTTP_404_NOT_FOUND)
    
    if not candidate_skills:
        return Response({'message': 'Candidate profile has no skills information.', 'jobs': []}, status=status.HTTP_200_OK)
    job_posts = JobPost.objects.all() 

    if not job_posts.exists():
        return Response({'message': 'No job posts available.', 'jobs': []}, status=status.HTTP_200_OK)

    recommended_jobs = recommend_jobs(candidate_skills, job_posts) 

    serializer = JobPostSerializer(recommended_jobs, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
def get_advice_from_tags(request):
    candidate_id = request.data.get('candidate_id')

    if not candidate_id:
        return Response({'error': 'Candidate ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        candidate_profile = UserProfile.objects.get(pk=candidate_id)
    except UserProfile.DoesNotExist:
        return Response({'error': 'Candidate profile not found.'}, status=status.HTTP_404_NOT_FOUND)

    try:
        candidate_skills = candidate_profile.tags
    except UserProfile.DoesNotExist:
        return Response({'error': 'User profile extra not found for this user.'}, status=status.HTTP_404_NOT_FOUND)

    if not candidate_skills:
        return Response({'message': 'Candidate profile has no skills information.'}, status=status.HTTP_200_OK)

    try:
        candidate_skills_list = [skill.strip().lower() for skill in candidate_skills.split(',') if candidate_skills and skill.strip()]
        if candidate_skills_list:
            general_advice = get_gemini_advice_consolidated(candidate_skills_list)
        else:
            general_advice = ""

        return Response({'advice': general_advice}, status=status.HTTP_200_OK)

    except Exception as e:
        logger.exception(f"An unexpected error occurred: {str(e)}")
        return Response({'error': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def get_gemini_advice_consolidated(skills):
    if not skills:
        return ""

    prompt = f"Provide advice for someone learning the following skills: {', '.join(skills)}. Include their importance and industry demand and latest tech trends. Format your response as a single paragraph."
    gemini_response = call_gemini_api(prompt)
    return gemini_response

def call_gemini_api(prompt):
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "google/gemini-flash-1.5",
        "messages": [{"role": "user", "content": prompt}]
    }
    try:
        response = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        gemini_response = response.json()
        return gemini_response.get('choices', [{}])[0].get('message', {}).get('content', '')
    except requests.exceptions.RequestException as e:
        print(f"Gemini API Error: {e}")
        return f"Gemini API Error: {e}"
    except (json.JSONDecodeError, KeyError) as e:
        print(f"JSON decode or key error: {e}")
        return f"JSON decode or key error: {e}"
    
@api_view(['GET', 'POST'])
def job_post_list(request):
    if request.method == 'GET':
        user_id = request.data.get('user')
        if user_id:
            try:
                user_profile = UserProfile.objects.get(pk=user_id)
            except UserProfile.DoesNotExist:
                return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)

            job_posts = JobPost.objects.filter(user=user_profile)
        else:
            job_posts = JobPost.objects.all()

        # Apply filters if provided
        country = request.GET.get('country')
        if country:
            job_posts = job_posts.filter(country__iexact=country)

        job_type = request.GET.get('jobType') 
        if job_type:
            job_posts = job_posts.filter(experience_level__iexact=job_type) 

        industry = request.GET.get('industry')
        if industry:
            job_posts = job_posts.filter(industry__iexact=industry)

        experience = request.GET.get('experience') 
        if experience:
            job_posts = job_posts.filter(experience_level__iexact=experience)

        job_function = request.GET.get('jobFunction') 
        if job_function:
            job_posts = job_posts.filter(job_function__iexact=job_function)

        job_title = request.GET.get('jobTitle') 
        if job_title:
            job_posts = job_posts.filter(job_title__icontains=job_title) 

        serializer = JobPostSerializer(job_posts, many=True)
        return Response(serializer.data)
    elif request.method == 'POST':
        user = request.data.get('user')
        if not user:
            return Response({'error': 'user ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_profile = UserProfile.objects.get(pk=user)
        except UserProfile.DoesNotExist:
            return Response({'error': 'Candidate profile not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = JobPostSerializer(data=request.data)
        if serializer.is_valid():
            description = serializer.validated_data['details']
            instance = serializer.save(user=user_profile)
            extracted_tags = get_openrouter_tags(description)
            if extracted_tags is not None:
                instance.tags = ", ".join(extracted_tags)
                instance.save()
            else:
                instance.tags = ""

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'PATCH', 'DELETE'])
def job_post_detail(request, pk):
    try:
        job_post = JobPost.objects.get(pk=pk)
    except JobPost.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = JobPostSerializer(job_post)
        return Response(serializer.data)

    elif request.method == 'PUT' or request.method == 'PATCH':
        user = request.data.get('user')
        if not user:
            return Response({'error': 'user ID is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_profile = UserProfile.objects.get(pk=user)
        except UserProfile.DoesNotExist:
            return Response({'error': 'Candidate profile not found.'}, status=status.HTTP_404_NOT_FOUND)        
        serializer = JobPostSerializer(job_post, data=request.data, partial=request.method == 'PATCH') 
        if serializer.is_valid():
            description = serializer.validated_data['details']
            instance = serializer.save(user=user_profile)
            extracted_tags = get_openrouter_tags(description)
            if extracted_tags is not None:
                instance.tags = ", ".join(extracted_tags)
                instance.save()
            else:
                instance.tags = ""

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        job_post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

def get_openrouter_tags(text):
    if not text:
        return []

    try:
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "google/gemini-flash-1.5",
            "messages": [{"role": "user", "content": f"Create a comma-separated list of relevant skills for this job description. These skills help to find the expected job for a job recommendation system.:\n{text}"}] 

        }

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            data=json.dumps(payload),
            timeout=10  
        )
        response.raise_for_status()  

        json_response = response.json() 
        content = json_response['choices'][0]['message']['content'] 
        tags = [tag.strip().lower() for tag in content.split(',')]  

        return tags

    except requests.exceptions.RequestException as e:
        logger.error(f"OpenRouter API Error: {e}") 
        if isinstance(e, requests.exceptions.Timeout):
            logger.error("OpenRouter API request timed out.")
        return None 

    except (json.JSONDecodeError, KeyError) as e:  
        logger.error(f"Error processing OpenRouter response: {e}")
        return None  
    
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt  # Exempt from CSRF for simplicity (handle properly in production)
def chatbot_endpoint(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user_message = data.get('message')

            if not user_message:
                return JsonResponse({'error': 'No message provided'}, status=400)

            if not OPENROUTER_API_KEY:
                return JsonResponse({'error': 'API key not set'}, status=500)

            api_url = "https://openrouter.ai/api/v1/chat/completions"

            payload = {
                "model": "google/gemini-flash-1.5",
                "messages": [{"role": "user", "content": user_message}]
            }

            headers = {
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json"
            }

            response = requests.post(api_url, headers=headers, data=json.dumps(payload))

            if response.status_code == 200:
                ai_reply = response.json()['choices'][0]['message']['content']
                return JsonResponse({'message': ai_reply})
            else:
                print(response.status_code, response.text)  # Debugging
                return JsonResponse({'error': 'Error with AI API'}, status=500)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except requests.exceptions.RequestException as e:
            print(e)
            return JsonResponse({'error': 'Error with AI API'}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=405)     