"""
URL configuration for project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path , include
from users.views import LoginView, UploadVoiceView,admin_images,home_view,voice_registration,voice_login,verify_voice
from django.views.generic import TemplateView
from django.conf.urls.static import static
from django.conf import settings
from django.conf.urls import handler404
from django.contrib.auth.decorators import login_required, user_passes_test

app_name = 'users'
handler404 = 'users.views.error_404_view'

def is_user(user):
    return user.is_authenticated

urlpatterns = [
    # path('', LoginView.as_view(), name='login'),
    path('admin/', admin.site.urls),
    path('', TemplateView.as_view(template_name='login.html'), name='login'),
    path('login/', TemplateView.as_view(template_name='login.html'), name='login'),
    path('signup/', TemplateView.as_view(template_name='signup.html'), name='signup'),
    path('forgot/', TemplateView.as_view(template_name='forgot.html'), name='forgot'),
    path('reset/', TemplateView.as_view(template_name='reset.html'), name='reset'),
    path('verify/', TemplateView.as_view(template_name='verify.html'), name='verify'),
    path('home/', home_view, name='home'),
    path('voice_registration/', voice_registration, name='voice_registration'),
    path('verify_voice/', verify_voice, name='verify_voice'),

    path('profile/voice/register/',voice_registration, name='voice_registration'),
    path('profile/voice/login/', voice_login, name='voice_login'),
    path('garbage/',TemplateView.as_view(template_name='query.html'), name='query'),
    path('upload_voice/', UploadVoiceView.as_view(), name='upload-voice'),

    path('admin/images/', admin_images, name='admin_images'),
    path('api/', include('users.urls')),    
    # path('admin/', include('admin_soft.urls')),

] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT) + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
