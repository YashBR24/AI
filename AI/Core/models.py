from django.db import models
from django.contrib.auth.models import User
import uuid
from datetime import timedelta
from django.utils import timezone

class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reset_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_when = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Password reset for {self.user.username} at {self.created_when}"

class EmailVerification(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Email verification for {self.user.username}"

    @property
    def is_expired(self):
        # Link expires after 24 hours
        return timezone.now() > self.created_at + timedelta(hours=24)

class LoginAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    username = models.CharField(max_length=255)
    attempt_time = models.DateTimeField(auto_now_add=True)
    was_successful = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Login attempt by {self.username} from {self.ip_address} at {self.attempt_time}"

class RegistrationAttempt(models.Model):
    ip_address = models.GenericIPAddressField()
    attempt_time = models.DateTimeField(auto_now_add=True)
    was_successful = models.BooleanField(default=False)
    
    def __str__(self):
        return f"Registration attempt from {self.ip_address} at {self.attempt_time}"

from django.db import models
from django.contrib.auth.models import User

class ActivityLog(models.Model):
    ACTIVITY_TYPES = [
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('REGISTER', 'Registration'),
        ('PASSWORD_RESET', 'Password Reset'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('PAGE_VIEW', 'Page View'),
        ('CONTACT', 'Contact Form'),
        ('UPLOAD', 'Upload'),  # Added from your previous context
        ('COMPRESSION', 'Compression'),  # Added from your previous context
        ('DOWNLOAD', 'Download'),  # Added from your previous context
        ('ERROR', 'Error'),  # Added from your previous context
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    activity_type = models.CharField(max_length=50, choices=ACTIVITY_TYPES)
    ip_address = models.CharField(max_length=45)
    details = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.activity_type} by {self.user.username if self.user else 'Anonymous'} at {self.created_at}"

    class Meta:
        ordering = ['-created_at']  # Fixed to use 'created_at' instead of 'timestamp'
        
class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    
    def __str__(self):
        return f"Contact from {self.name} at {self.created_at}"

    class Meta:
        ordering = ['-created_at']