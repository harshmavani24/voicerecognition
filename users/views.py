from tkinter import Image
from django.shortcuts import render
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from .serializers import UserSerializer, VerifyAccountSerializer,ForgotPasswordSerializer, ResetPasswordSerializer,QuerySerializer
from rest_framework.response import Response
from .models import User,PendingUser
import jwt,datetime
from rest_framework.permissions import IsAuthenticated
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.shortcuts import redirect
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.crypto import get_random_string
from django.core.mail import EmailMessage
from rest_framework import status
import traceback
from django.contrib.auth.hashers import make_password
from django.utils.http import urlsafe_base64_decode
from django.http import HttpResponse
from urllib.parse import unquote
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.exceptions import NotFound
from django.http import JsonResponse
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model 

User = get_user_model()

def error_404_view(request, exception):
    return render(request, 'users/404.html', status=404)



class RegisterView(APIView):
    def post(self, request):
        User = get_user_model()
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # user = serializer.save()
        user_data = serializer.validated_data

        pending_user = PendingUser.objects.create(name=user_data['name'], email=user_data['email'], phone=user_data['phonenumber'], password=user_data['password'])

        # Generate OTP and send email
        otp = get_random_string(length=6, allowed_chars='0123456789')
        pending_user.otp = otp
        pending_user.save()

        # Send OTP email
        subject = 'OTP Verification'
        message = render_to_string('registration/otp_email.html', {'otp': otp})
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [pending_user.email]
        email = EmailMessage(subject, message, from_email, recipient_list)
        email.content_subtype = 'html' 
        email.send()
        
        if User.objects.filter(email=email).exists():
            return Response({'status': status.HTTP_400_BAD_REQUEST, 'message': 'Email already exists', 'data': None})
        redirect_url = 'http://127.0.0.1:8000/verify?email=' + pending_user.email
        return JsonResponse({'redirect_url': redirect_url})
        # return Response({'success': True, 'data': serializer.data}, status=status.HTTP_201_CREATED)
        # return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        user = User.objects.filter(email=email).first()
        
        if user is None:
            raise AuthenticationFailed('User not found')
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password')
        if user.is_active == False:
            raise AuthenticationFailed('Account disabled')
        if not user.is_verified:
            otp = get_random_string(length=6, allowed_chars='0123456789')
            user.otp = otp
            user.save()
            # Send OTP email
            subject = 'OTP Verification'
            message = render_to_string('registration/otp_email.html', {'otp': otp})
            from_email = settings.DEFAULT_FROM_EMAIL
            recipient_list = [user.email]
            email = EmailMessage(subject, message, from_email, recipient_list)
            email.content_subtype = 'html' 
            email.send()
            redirect_url = 'http://127.0.0.1:8000/verify'  # Replace with your desired redirect URL
            return JsonResponse({'redirect_url': redirect_url})
            # raise AuthenticationFailed('Account not verified')

        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60000),
            'iat': datetime.datetime.utcnow()
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')
        response = HttpResponse()
        response.set_cookie('jwt', token, httponly=True)  # Set the 'jwt' cookie

        # Return a success response
        return response
        # Render the login.html template with the user's email and token
        # return render(request, 'login.html', {'email': email, 'token': token})


class DeleteUserView(APIView):
    def delete(self, request):
        user_id = request.data.get('id')
        try:
            user = PendingUser.objects.get(id=user_id)
            user.delete()
            return Response("User record deleted successfully", status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response("User not found", status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(f"An error occurred: {str(e)}", status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserView(APIView):
    # permission_classes = [IsAuthenticated]
    def get(self,request):
        token = request.COOKIES.get('jwt')
        # return Response(token)
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token,'secret',algorithms=['HS256'])
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated')
        
        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        return Response(serializer.data)
    
class LogoutView(APIView):
    def post(self,request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message':'success'
        }
        return response


class VerifyOTP(APIView):
    def post(self, request):
        try:
            serializer = VerifyAccountSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']

            pending_user = PendingUser.objects.filter(email=email, otp=otp).first()

            if not pending_user:
                return Response({
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid email',
                    'data': {}
                })

            # Check if more than 2 minutes have passed since the creation of the pending user
            if pending_user.created_at + timedelta(minutes=2) < timezone.now():
                pending_user.delete()
                return Response({
                    'status': status.HTTP_400_BAD_REQUEST,
                    'message': 'Account verification expired. Please sign up again.',
                    'data': {}
                })

            user = User.objects.create_user(
                name=pending_user.name,
                email=pending_user.email,
                password=pending_user.password,
                first_name=pending_user.name,
                is_active=True,
                is_verified=True,
                otp='verified',
                is_staff=False,
                is_superuser=False,
                last_name='',
                phonenumber=pending_user.phone
            )
            user.save()
            pending_user.delete()
            return Response({
                'status': status.HTTP_200_OK,
                'message': 'Account verified successfully',
                'data': {}
            })
            # ... Rest of the code
            # Update user's verification status, return response, etc.

        except Exception as e:
            print(e)
            traceback.print_exc()  # Print the exception traceback for debugging
            return Response({
                'status': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Something went wrong',
                'data': {}
            })
    
        


class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        user = User.objects.filter(email=email).first()
        if user is None:
            raise AuthenticationFailed('User not found')

        token_generator = PasswordResetTokenGenerator()
        uidb64 = urlsafe_base64_encode(force_bytes(user.id))
        token = token_generator.make_token(user)
        reset_link = f'http://{get_current_site(request).domain}/reset' + f'?uidb64={uidb64}&token={token}'
        # reset_link = f"http://{get_current_site(request).domain}/reset-password/{user.id}/{token}"
        user.forgot_token = token
        user.save()
        subject = 'Forgot Password - Reset Link'
        message = render_to_string('registration/forgot_password_email.html', {
            'user': user,
            'reset_link': reset_link,
            'domain': get_current_site(request).domain,
        })
        email = EmailMessage(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
        email.content_subtype = 'html' 
        email.send()
        response = HttpResponse()
        # return response
        return Response({'success':True,'message': 'Reset link sent successfully'})

class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = request.query_params.get('token')  # Extract token from query parameters
        new_password = serializer.validated_data['new_password']

        try:
            uidb64 = request.query_params.get('uidb64')  # Extract uidb64 from query parameters
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise AuthenticationFailed('Invalid reset token')

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            raise AuthenticationFailed('Invalid reset token')

        user.password = make_password(new_password)
        user.forgot_token = None
        user.save()

        return Response({'message': 'Password reset successful'})


from rest_framework.parsers import MultiPartParser, FormParser

class QuerySubmission(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        serializer = QuerySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'status': status.HTTP_201_CREATED,
                'message': 'Query submitted successfully',
                'data': serializer.data
            })
        else:
            return Response({
                'status': status.HTTP_400_BAD_REQUEST,
                'message': 'Invalid data',
                'errors': serializer.errors
            })
            
            
# make class for register_voice in that class two method one is post and secnd is get. get can only load data  voice_registration.html page when user are go to /register_voice url. and post method is use for save data in database. and that post request have stored user voice and also save user id 

            
from django.contrib.admin.views.decorators import staff_member_required
from django.http import HttpResponseForbidden
from django.shortcuts import render
from django.conf import settings
from sendfile import sendfile

@staff_member_required
def admin_images(request):
    if not request.user.is_superuser:
        return HttpResponseForbidden("You are not authorized to access this directory.")

    # Construct the full file path
    file_path = settings.MEDIA_ROOT + '/query_photos/'

    # Use the sendfile package to serve the file
    return sendfile(request, file_path, attachment=True)

from django.views.generic import TemplateView
from .decorators import jwt_token_required

@jwt_token_required
def home_view(request):
    # Your view logic goes here
    return render(request, 'home.html')

def voice_registration(request):
    return render(request,'voice_registration.html')

def voice_login(request):
    if request.method == 'GET':
        return render(request,'voice_login.html')
    if request.method == 'POST':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            r.adjust_for_ambient_noise(source)
            print("Please say something")
            audio = r.listen(source)
            print("Recognizing Now .... ")

            try:
                recognized_text = r.recognize_google(audio)
                print("You have said: " + recognized_text)
            except sr.UnknownValueError:
                print("Google Speech Recognition could not understand audio")
                recognized_text = None
            except sr.RequestError as e:
                print(f"Could not request results from Google Speech Recognition service; {e}")
                recognized_text = None

            save_path = os.path.join("media", "recorded.wav")
            with open(save_path, "wb") as f:
                f.write(audio.get_wav_data())

            response_data = {
                "success": True,
                "recognized_text": recognized_text,
                "message": "Voice recording saved successfully.",
            }
            return JsonResponse(response_data)
import os
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View

from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

MEDIA_DIR = os.path.join(settings.BASE_DIR, 'reference_voice')

@method_decorator(csrf_exempt, name='dispatch')
class UploadVoiceView(View):
    def post(self, request, *args, **kwargs):
        try:
            audio_file = request.FILES['audio']

            # Save the audio file as '1.wav' in the 'reference_voice' directory.
            with open(os.path.join(MEDIA_DIR, '1.wav'), 'wb') as destination:
                for chunk in audio_file.chunks():
                    destination.write(chunk)

            return JsonResponse({'message': 'Audio saved successfully'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)


# Import the speech recognition library
import speech_recognition as sr
import os
import speech_recognition as sr
from django.shortcuts import render
from django.http import JsonResponse

def voice_registration(request):
    if request.method == 'POST':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            r.adjust_for_ambient_noise(source)
            print("Please say something")
            audio = r.listen(source)
            print("Recognizing Now .... ")

            try:
                recognized_text = r.recognize_google(audio)
                print("You have said: " + recognized_text)
            except sr.UnknownValueError:
                print("Google Speech Recognition could not understand audio")
                recognized_text = None
            except sr.RequestError as e:
                print(f"Could not request results from Google Speech Recognition service; {e}")
                recognized_text = None

            # Save the recorded audio (adjust the path as needed)
            save_path = os.path.join("media", "recorded.wav")
            with open(save_path, "wb") as f:
                f.write(audio.get_wav_data())

            response_data = {
                "success": True,
                "recognized_text": recognized_text,
                "message": "Voice recording saved successfully.",
            }
            return JsonResponse(response_data)

    return render(request, 'voice_registration.html')


# Helper function to calculate text similarity
# def calculate_similarity(text1, text2):
#     # Function to calculate similarity between two strings using Levenshtein distance
    
#     # Length of the input strings
#     len_text1 = len(text1)
#     len_text2 = len(text2)

#     # Create a matrix to store Levenshtein distances
#     distance_matrix = [[0] * (len_text2 + 1) for _ in range(len_text1 + 1)]

#     # Initialize the matrix
#     for i in range(len_text1 + 1):
#         distance_matrix[i][0] = i
#     for j in range(len_text2 + 1):
#         distance_matrix[0][j] = j

#     # Fill in the matrix
#     for i in range(1, len_text1 + 1):
#         for j in range(1, len_text2 + 1):
#             cost = 0 if text1[i - 1] == text2[j - 1] else 1
#             distance_matrix[i][j] = min(
#                 distance_matrix[i - 1][j] + 1,  # Deletion
#                 distance_matrix[i][j - 1] + 1,  # Insertion
#                 distance_matrix[i - 1][j - 1] + cost  # Substitution
#             )

#     # Calculate similarity as a value between 0 and 1
#     max_len = max(len_text1, len_text2)
#     similarity = 1 - (distance_matrix[len_text1][len_text2] / max_len)

#     return similarity

@csrf_exempt
def voice_registration(request):
    if request.method == 'POST':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            r.adjust_for_ambient_noise(source)
            print("Please say something")
            audio = r.listen(source)
            print("Recognizing Now .... ")

            try:
                recognized_text = r.recognize_google(audio)
                print("You have said: " + recognized_text)
            except sr.UnknownValueError:
                print("Google Speech Recognition could not understand audio")
                recognized_text = None
            except sr.RequestError as e:
                print(f"Could not request results from Google Speech Recognition service; {e}")
                recognized_text = None

            save_path = os.path.join("media", "recorded.wav")
            with open(save_path, "wb") as f:
                f.write(audio.get_wav_data())

            response_data = {
                "success": True,
                "recognized_text": recognized_text,
                "message": "Voice recording saved successfully.",
            }
            return JsonResponse(response_data)

    return render(request, 'voice_registration.html')
# phase 2 render .html view code
@csrf_exempt
def voice_registration2(request):
    if request.method == 'POST':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            r.adjust_for_ambient_noise(source)
            print("Please say something")
            audio = r.listen(source)
            print("Recognizing Now .... ")

            try:
                recognized_text = r.recognize_google(audio)
                print("You have said: " + recognized_text)
            except sr.UnknownValueError:
                print("Google Speech Recognition could not understand audio")
                recognized_text = None
            except sr.RequestError as e:
                print(f"Could not request results from Google Speech Recognition service; {e}")
                recognized_text = None

            save_path = os.path.join("media", "recorded.wav")
            with open(save_path, "wb") as f:
                f.write(audio.get_wav_data())

            response_data = {
                "success": True,
                "recognized_text": recognized_text,
                "message": "Voice recording saved successfully.",
            }
            return JsonResponse(response_data)

    return render(request, 'phase2.html')

def voice_registration3(request):
    if request.method == 'POST':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            r.adjust_for_ambient_noise(source)
            print("Please say something")
            audio = r.listen(source)
            print("Recognizing Now .... ")

            try:
                recognized_text = r.recognize_google(audio)
                print("You have said: " + recognized_text)
            except sr.UnknownValueError:
                print("Google Speech Recognition could not understand audio")
                recognized_text = None
            except sr.RequestError as e:
                print(f"Could not request results from Google Speech Recognition service; {e}")
                recognized_text = None

            save_path = os.path.join("media", "recorded.wav")
            with open(save_path, "wb") as f:
                f.write(audio.get_wav_data())

            response_data = {
                "success": True,
                "recognized_text": recognized_text,
                "message": "Voice recording saved successfully.",
            }
            return JsonResponse(response_data)

    return render(request, 'phase3.html')

def voice_registration4(request):
    if request.method == 'POST':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            r.adjust_for_ambient_noise(source)
            print("Please say something")
            audio = r.listen(source)
            print("Recognizing Now .... ")

            try:
                recognized_text = r.recognize_google(audio)
                print("You have said: " + recognized_text)
            except sr.UnknownValueError:
                print("Google Speech Recognition could not understand audio")
                recognized_text = None
            except sr.RequestError as e:
                print(f"Could not request results from Google Speech Recognition service; {e}")
                recognized_text = None

            save_path = os.path.join("media", "recorded.wav")
            with open(save_path, "wb") as f:
                f.write(audio.get_wav_data())

            response_data = {
                "success": True,
                "recognized_text": recognized_text,
                "message": "Voice recording saved successfully.",
            }
            return JsonResponse(response_data)

    return render(request, 'phase4.html')

def voice_registration5(request):
    if request.method == 'POST':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            r.adjust_for_ambient_noise(source)
            print("Please say something")
            audio = r.listen(source)
            print("Recognizing Now .... ")

            try:
                recognized_text = r.recognize_google(audio)
                print("You have said: " + recognized_text)
            except sr.UnknownValueError:
                print("Google Speech Recognition could not understand audio")
                recognized_text = None
            except sr.RequestError as e:
                print(f"Could not request results from Google Speech Recognition service; {e}")
                recognized_text = None

            save_path = os.path.join("media", "recorded.wav")
            with open(save_path, "wb") as f:
                f.write(audio.get_wav_data())

            response_data = {
                "success": True,
                "recognized_text": recognized_text,
                "message": "Voice recording saved successfully.",
            }
            return JsonResponse(response_data)

    return render(request, 'phase5.html')



from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import assemblyai as aai
import os
import re
# Set the API key for AssemblyAI
aai.settings.api_key = "1d45957af17045c397d880ce1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MEDIA_DIR = os.path.join(BASE_DIR, 'voicesamples')

# Ensure the media directory exists
if not os.path.exists(MEDIA_DIR):
    os.makedirs(MEDIA_DIR)

@csrf_exempt
def phase1(request):
    if request.method == 'POST' and request.FILES['audio']:
        audio_file = request.FILES['audio']

        # Get the user's mobile number from the file name
        file_name = audio_file.name
        userMobile = file_name.split('_')[0]  # Assuming the mobile number is at the beginning of the file name

        # Save the audio file in the media directory with the correct file name format
        file_path = os.path.join(MEDIA_DIR, file_name)
        with open(file_path, 'wb+') as destination:
            for chunk in audio_file.chunks():
                destination.write(chunk)
        def levenshtein_distance(s, t):
                """
                Compute the Levenshtein distance between two strings.
                """
                if len(s) > len(t):
                    s, t = t, s

                # Previous row of distances
                previous_row = range(len(t) + 1)

                for i, c1 in enumerate(s):
                    # Current row of distances
                    current_row = [i + 1]

                    for j, c2 in enumerate(t):
                        insertions = previous_row[j + 1] + 1  # j+1 instead of j since previous_row and current_row are one character longer
                        deletions = current_row[j] + 1        # than s and t
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))

                    # Previous row of distances becomes current row
                    previous_row = current_row

                return previous_row[-1]
            
        # Transcribe the saved audio file
        transcriber = aai.Transcriber()
        try:
            transcript = transcriber.transcribe(file_path)

            # Remove special characters and spaces from the transcribed text
            transcribed_text_cleaned = ''.join(re.split(r'[-., ]', transcript.text))
            transcribed_text_cleaned = transcribed_text_cleaned.upper()  # Convert to uppercase

            # Original given text
            original_text = 'Thequickbrownfoxjumpsoverthelazydog'
            original_text = original_text.upper()   # Convert to uppercase

            
            edit_distance = levenshtein_distance(transcribed_text_cleaned, original_text)

            # Set a threshold for allowed edit distance
            threshold = 5  # Adjust as needed

            if edit_distance <= threshold:
                return JsonResponse({'message': transcribed_text_cleaned})
            else:
                return JsonResponse({'error': transcribed_text_cleaned}, status=400)
        except Exception as e:
            # Optionally, if there's an error, you can remove the audio file
            # os.remove(file_path)
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

    

@csrf_exempt
def phase2(request):
    if request.method == 'POST' and request.FILES['audio']:
        audio_file = request.FILES['audio']

        # Get the user's mobile number from the file name
        file_name = audio_file.name
        userMobile = file_name.split('_')[0]  # Assuming the mobile number is at the beginning of the file name

        # Save the audio file in the media directory with the correct file name format
        file_path = os.path.join(MEDIA_DIR, file_name)
        with open(file_path, 'wb+') as destination:
            for chunk in audio_file.chunks():
                destination.write(chunk)

        def levenshtein_distance(s, t):
            """
            Compute the Levenshtein distance between two strings.
            """
            if len(s) > len(t):
                s, t = t, s

            # Previous row of distances
            previous_row = range(len(t) + 1)

            for i, c1 in enumerate(s):
                # Current row of distances
                current_row = [i + 1]

                for j, c2 in enumerate(t):
                    insertions = previous_row[j + 1] + 1  # j+1 instead of j since previous_row and current_row are one character longer
                    deletions = current_row[j] + 1        # than s and t
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))

                # Previous row of distances becomes current row
                previous_row = current_row

            return previous_row[-1]

        # Transcribe the saved audio file
        transcriber = aai.Transcriber()
        try:
            transcript = transcriber.transcribe(file_path)

            # Remove special characters and spaces from the transcribed text
            transcribed_text_cleaned = ''.join(re.split(r'[-., ]', transcript.text))

            # Original given text
            original_text = 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG'
            # original_text = 'ABCDEFGHIJKLM'
            # original_text = original_text.upper()   # Convert to uppercase

            edit_distance = levenshtein_distance(transcribed_text_cleaned, original_text)

            # Set a threshold for allowed edit distance
            threshold = 5  # Adjust as needed

            if edit_distance <= threshold:
                return JsonResponse({'message': transcribed_text_cleaned})
            else:
                return JsonResponse({'error': transcribed_text_cleaned}, status=400)
        except Exception as e:
            # Optionally, if there's an error, you can remove the audio file
            # os.remove(file_path)
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)


    


@csrf_exempt
def phase3(request):
    if request.method == 'POST' and request.FILES['audio']:
        audio_file = request.FILES['audio']
        file_name = audio_file.name
        userMobile = file_name.split('_')[0]
        # Save the audio file in the media directory
        file_path = os.path.join(MEDIA_DIR, file_name)
        with open(file_path, 'wb+') as destination:
            for chunk in audio_file.chunks():
                destination.write(chunk)

        def levenshtein_distance(s, t):
                """
                Compute the Levenshtein distance between two strings.
                """
                if len(s) > len(t):
                    s, t = t, s

                # Previous row of distances
                previous_row = range(len(t) + 1)

                for i, c1 in enumerate(s):
                    # Current row of distances
                    current_row = [i + 1]

                    for j, c2 in enumerate(t):
                        insertions = previous_row[j + 1] + 1  # j+1 instead of j since previous_row and current_row are one character longer
                        deletions = current_row[j] + 1        # than s and t
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))

                    # Previous row of distances becomes current row
                    previous_row = current_row

                return previous_row[-1]
            
        # Transcribe the saved audio file
        transcriber = aai.Transcriber()
        try:
            transcript = transcriber.transcribe(file_path)

            # Remove special characters and spaces from the transcribed text
            transcribed_text_cleaned = ''.join(re.split(r'[-., ]', transcript.text))
            transcribed_text_cleaned = transcribed_text_cleaned.upper()  # Convert to uppercase

            # Original given text
            # original_text = 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG'
            original_text = 'ABCDEFGHIJKLM'
            # original_text = original_text.upper()   # Convert to uppercase

            
            edit_distance = levenshtein_distance(transcribed_text_cleaned, original_text)

            # Set a threshold for allowed edit distance
            threshold = 5  # Adjust as needed

            if edit_distance <= threshold:
                return JsonResponse({'message': transcribed_text_cleaned})
            else:
                return JsonResponse({'error': transcribed_text_cleaned}, status=400)
        except Exception as e:
            # Optionally, if there's an error, you can remove the audio file
            os.remove(file_path)
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

    

@csrf_exempt
def phase4(request):
    if request.method == 'POST' and request.FILES['audio']:
        audio_file = request.FILES['audio']
        file_name = audio_file.name
        userMobile = file_name.split('_')[0]
        # Save the audio file in the media directory
        file_path = os.path.join(MEDIA_DIR, file_name)
        with open(file_path, 'wb+') as destination:
            for chunk in audio_file.chunks():
                destination.write(chunk)
        def levenshtein_distance(s, t):
                """
                Compute the Levenshtein distance between two strings.
                """
                if len(s) > len(t):
                    s, t = t, s

                # Previous row of distances
                previous_row = range(len(t) + 1)

                for i, c1 in enumerate(s):
                    # Current row of distances
                    current_row = [i + 1]

                    for j, c2 in enumerate(t):
                        insertions = previous_row[j + 1] + 1  # j+1 instead of j since previous_row and current_row are one character longer
                        deletions = current_row[j] + 1        # than s and t
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))

                    # Previous row of distances becomes current row
                    previous_row = current_row

                return previous_row[-1]
            
        # Transcribe the saved audio file
        transcriber = aai.Transcriber()
        try:
            transcript = transcriber.transcribe(file_path)

            # Remove special characters and spaces from the transcribed text
            transcribed_text_cleaned = ''.join(re.split(r'[-., ]', transcript.text))
            transcribed_text_cleaned = transcribed_text_cleaned.upper()  # Convert to uppercase

            # Original given text
            original_text = 'TheearlybirdgetsthewormAnappleadaykeepsthedoctoraway'
            # original_text = original_text.upper()   # Convert to uppercase

            
            edit_distance = levenshtein_distance(transcribed_text_cleaned, original_text)

            # Set a threshold for allowed edit distance
            threshold = 5  # Adjust as needed

            if edit_distance <= threshold:
                return JsonResponse({'message': transcribed_text_cleaned})
            else:
                return JsonResponse({'error': transcribed_text_cleaned}, status=400)
        except Exception as e:
            # Optionally, if there's an error, you can remove the audio file
            os.remove(file_path)
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

@csrf_exempt
def phase5(request):
    if request.method == 'POST' and request.FILES['audio']:
        audio_file = request.FILES['audio']
        file_name = audio_file.name
        userMobile = file_name.split('_')[0]
        # Save the audio file in the media directory
        file_path = os.path.join(MEDIA_DIR, file_name)
        with open(file_path, 'wb+') as destination:
            for chunk in audio_file.chunks():
                destination.write(chunk)

        def levenshtein_distance(s, t):
                """
                Compute the Levenshtein distance between two strings.
                """
                if len(s) > len(t):
                    s, t = t, s

                # Previous row of distances
                previous_row = range(len(t) + 1)

                for i, c1 in enumerate(s):
                    # Current row of distances
                    current_row = [i + 1]

                    for j, c2 in enumerate(t):
                        insertions = previous_row[j + 1] + 1  # j+1 instead of j since previous_row and current_row are one character longer
                        deletions = current_row[j] + 1        # than s and t
                        substitutions = previous_row[j] + (c1 != c2)
                        current_row.append(min(insertions, deletions, substitutions))

                    # Previous row of distances becomes current row
                    previous_row = current_row

                return previous_row[-1]
            
        # Transcribe the saved audio file
        transcriber = aai.Transcriber()
        try:
            transcript = transcriber.transcribe(file_path)

            # Remove special characters and spaces from the transcribed text
            transcribed_text_cleaned = ''.join(re.split(r'[-., ]', transcript.text))
            transcribed_text_cleaned = transcribed_text_cleaned.upper()  # Convert to uppercase

            # Original given text
            original_text = 'Zeroonetwothreefourfivesixseveneightnineten'
            # original_text = original_text.upper()   # Convert to uppercase

            
            edit_distance = levenshtein_distance(transcribed_text_cleaned, original_text)

            # Set a threshold for allowed edit distance
            threshold = 5  # Adjust as needed

            if edit_distance <= threshold:
                return JsonResponse({'message': transcribed_text_cleaned})
            else:
                return JsonResponse({'error': transcribed_text_cleaned}, status=400)
        except Exception as e:
            # Optionally, if there's an error, you can remove the audio file
            # os.remove(file_path)
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)
    
from django.http import JsonResponse
from django.views import View
from .voice_recognition import train_voice_model, predict_user_voice

class TrainVoiceModelView(View):
    def get(self, request, *args, **kwargs):
        try:
            train_voice_model()
            return JsonResponse({"status": "success", "message": "Model trained successfully!"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})

class PredictUserVoiceView(View):
    def get(self, request, *args, **kwargs):
        try:
            result = predict_user_voice()
            return JsonResponse({"status": "success", "predicted_user": result})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})

def voice_recognition_page(request):
    return render(request, 'voice_recognition.html')

# click method
@csrf_exempt
def voice_login(request):
    if request.method == 'POST':
        r = sr.Recognizer()
        with sr.Microphone() as source:
            r.adjust_for_ambient_noise(source)
            print("Please say something")
            audio = r.listen(source)
            print("Recognizing Now .... ")

            try:
                recognized_text = r.recognize_google(audio)
                print("You have said: " + recognized_text)
            except sr.UnknownValueError:
                print("Google Speech Recognition could not understand audio")
                recognized_text = None
            except sr.RequestError as e:
                print(f"Could not request results from Google Speech Recognition service; {e}")
                recognized_text = None

            # Save the recorded audio (adjust the path as needed)
            save_path = os.path.join("media", "recorded.wav")
            with open(save_path, "wb") as f:
                f.write(audio.get_wav_data())

            response_data = {
                "success": True,
                "recognized_text": recognized_text,
                "message": "Voice recording saved successfully.",
            }
            return JsonResponse(response_data)

    return render(request, 'voice_login.html')

def voice_auth(request):
    if request.method == 'POST' and request.FILES['audio']:
        audio_file = request.FILES['audio']

        # Get the user's mobile number from the file name
        file_name = audio_file.name
        userMobile = file_name.split('_')[0]  # Assuming the mobile number is at the beginning of the file name

        # Save the audio file in the media directory with the correct file name format
        file_path = os.path.join(MEDIA_DIR, file_name)
        with open(file_path, 'wb+') as destination:
            for chunk in audio_file.chunks():
                destination.write(chunk)
        
    if request.method == 'GET':
        render(request, 'voice_login.html')
    else:
        return JsonResponse({'error': 'Invalid request'}, status=400)

# from django.http import JsonResponse
# from django.views.decorators.csrf import csrf_exempt
# import speech_recognition as sr  # Make sure to install the 'SpeechRecognition' library
# from pydub import AudioSegment
# import io
# import logging
# import difflib  # We'll use difflib to calculate similarity
# logging.basicConfig(filename='voice_verification.log', level=logging.DEBUG)
# def calculate_similarity(s1, s2):
#     if len(s1) < len(s2):
#         return calculate_similarity(s2, s1)

#     distances = range(len(s1) + 1)
#     for index2, char2 in enumerate(s2):
#         new_distances = [index2 + 1]
#         for index1, char1 in enumerate(s1):
#             if char1 == char2:
#                 new_distances.append(distances[index1])
#             else:
#                 new_distances.append(1 + min((distances[index1], distances[index1 + 1], new_distances[-1])))
#         distances = new_distances

#     return 1 - (distances[-1] / max(len(s1), len(s2)))
# @csrf_exempt
# def voice_with_assemblyai(request):
#     logging.debug('Received POST request to /verify_voice/')

#     if request.method == 'POST':
#         audio_file = request.FILES.get('audio')

#         # Check if the uploaded file is in a supported format
#         if not audio_file.name.lower().endswith(('.wav', '.aiff', '.aif', '.flac')):
#             return JsonResponse({'message': 'Unsupported audio format.'}, status=400)

#         # Convert the audio to PCM WAV format
#         try:
#             audio_data = AudioSegment.from_file(io.BytesIO(audio_file.read()))
#             audio_data = audio_data.set_channels(1).set_frame_rate(16000)  # Adjust channels and frame rate as needed
#             converted_audio_file = io.BytesIO()
#             audio_data.export(converted_audio_file, format='wav')
#             converted_audio_file.seek(0)
#         except Exception as e:
#             return JsonResponse({'message': f'Error converting audio: {str(e)}'}, status=400)

#         # Initialize the recognizer and perform speech recognition
#         recognizer = sr.Recognizer()

#         try:
#             with sr.AudioFile(converted_audio_file) as source:
#                 audio_data = recognizer.record(source)

#                 # Perform speech recognition
#                 recognized_text = recognizer.recognize_google(audio_data)  # You can use different recognition engines

#                 # Logging for successful recognition
#                 logging.debug('Speech recognition successful.')

#                 # Expected text for verification (A-Z alphabet)
#                 expected_text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#                 # Calculate similarity between recognized and expected text
#                 similarity = calculate_similarity(recognized_text.upper(), expected_text)

#                 if similarity >= 0.8:
#                     return JsonResponse({'message': 'Voice Successfully verified.'}, status=200)
#                 else:
#                     return JsonResponse({'message': 'Voice verification failed.'}, status=400)

#         except sr.UnknownValueError:
#             # Logging for failure to understand audio
#             logging.error('Could not understand audio.')

#         except sr.RequestError as e:
#             # Logging for speech recognition error
#             logging.error(f'Speech recognition error: {str(e)}')

#     # If the request method is not POST or there's an issue, return an error response
#     return JsonResponse({'message': 'Invalid request method or error occurred.'}, status=500)


''''
class VisitorListCreateView(generics.ListCreateAPIView):
    queryset = Visitor.objects.all()
    serializer_class = VisitorSerializer

class QueryListCreateView(generics.ListCreateAPIView):
    queryset = Query.objects.all()
    serializer_class = QuerySerializer
    
class RegistrationCreateView(generics.CreateAPIView):
    queryset = Registration.objects.all()
    serializer_class = RegistrationSerializer
'''

    
# class LoginView(APIView):
#     def post(self,request):
#         email = request.data['email']
#         password = request.data['password']
#         user = User.objects.filter(email=email).first()
#         if user is None:
#             raise AuthenticationFailed('User not found')
#         if not user.check_password(password):
#             raise AuthenticationFailed('Incorrect password')
#         if user.is_active == False:
#             raise AuthenticationFailed('Account disabled')
#         if user.is_verified == False:
#             raise AuthenticationFailed('Account not verified')
        
#         payload = {
#             'id':user.id,
#             'exp':datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
#             'iat':datetime.datetime.utcnow()
#         }
#         token = jwt.encode(payload,'secret',algorithm='HS256')
#         response = Response()
#         response.set_cookie(key='jwt',value=token,httponly=True)
#         response.data = {
#             'jwt':token
#         }
#         return response


