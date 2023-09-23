from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import RegisterView,LoginView,UserView,LogoutView,VerifyOTP,ForgotPasswordView,ResetPasswordView,DeleteUserView,QuerySubmission
urlpatterns = [
    path('register' ,RegisterView.as_view()),
    path('login' ,LoginView.as_view()),
    path('user' ,UserView.as_view()),
    path('logout' ,LogoutView.as_view()),
    path('verify', VerifyOTP.as_view()),
    path('forgot', ForgotPasswordView.as_view(), name='forgot_password'),
    path('reset', ResetPasswordView.as_view(), name='reset_password'),
    path('deleteUser', DeleteUserView.as_view(),name='delete_user'),
    path('query', QuerySubmission.as_view(), name='query_submission'),
    

]
urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
'''
    path('visitors/', views.VisitorListCreateView.as_view(), name='visitor-list-create'),
    path('queries/', views.QueryListCreateView.as_view(), name='query-list-create'),
    path('register/', views.RegistrationCreateView.as_view(), name='register'),
'''