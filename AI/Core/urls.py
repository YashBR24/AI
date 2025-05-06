from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.LandingView, name='landing'),
    path('index/', views.Home, name='home'),
    path('register/', views.RegisterView, name='register'),
    path('verify-email/<str:token>/', views.VerifyEmailView, name='verify-email'),
    path('login/', views.LoginView, name='login'),
    path('logout/', views.LogoutView, name='logout'),
    path('forgot-password/', views.ForgotPassword, name='forgot-password'),
    path('password-reset-sent/<str:reset_id>/', views.PasswordResetSent, name='password-reset-sent'),
    path('reset-password/<str:reset_id>/', views.ResetPassword, name='reset-password'),
    path('compress/', views.CompressView, name='compress'),
    path('log_download/', views.LogDownloadView, name='log_download'),
    path('profile/', views.UserProfileView, name='profile'),
    path('update-profile/', views.UpdateProfileView, name='update-profile'),
    path('contact/', views.ContactView, name='contact'),
    path('about/', views.AboutView, name='about'),
    path('generate/', views.generate_image, name='generate_image'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)