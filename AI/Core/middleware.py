from django.core.cache import cache
from django.http import HttpResponseForbidden
from datetime import datetime, timedelta
from .models import LoginAttempt, RegistrationAttempt, ActivityLog
from django.contrib import messages

class RateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path in ['/login/', '/register/']:
            ip_address = self.get_client_ip(request)
            
            # For login attempts
            if request.path == '/login/' and request.method == 'POST':
                username = request.POST.get('username', '')
                key = f'login_attempts_{username}'
                attempts = cache.get(key, 0)
                
                # Check if user is blocked
                if cache.get(f'block_user_{username}'):
                    messages.error(request, 'Too many failed login attempts. Account locked for 1 hour.')
                    return HttpResponseForbidden('Too many failed login attempts. Account locked for 1 hour.')
                
                if attempts >= 3:
                    cache.set(f'block_user_{username}', True, 3600)  # Block user for 1 hour
                    messages.error(request, 'Account locked due to too many failed attempts. Try again after 1 hour.')
                    return HttpResponseForbidden('Account locked due to too many failed attempts. Try again after 1 hour.')
                
                # Increment attempts only if login fails (we'll check this in the view)
                response = self.get_response(request)
                if response.status_code == 302 and '/login/' in response.url:  # Redirect back to login indicates failure
                    cache.set(key, attempts + 1, 3600)  # Reset after 1 hour
                elif response.status_code == 302 and '/home/' in response.url:  # Successful login
                    cache.delete(key)  # Reset attempts on successful login
                
                return response

            # For registration attempts (keeping IP-based for now, but can be changed if needed)
            if request.path == '/register/' and request.method == 'POST':
                key = f'register_attempts_{ip_address}'
                attempts = cache.get(key, 0)
                
                if attempts >= 4:
                    cache.set(f'block_ip_{ip_address}', True, 3600)  # Block IP for 1 hour
                    messages.error(request, 'Too many registration attempts. Try again after 1 hour.')
                    return HttpResponseForbidden('Too many registration attempts. Try again after 1 hour.')
                
                cache.set(key, attempts + 1, 3600)  # Reset after 1 hour

        # Log all page views
        if request.method == 'GET' and not request.path.startswith('/admin/'):
            ActivityLog.objects.create(
                user=request.user if request.user.is_authenticated else None,
                activity_type='PAGE_VIEW',
                ip_address=self.get_client_ip(request),
                details=f"Viewed page: {request.path}"
            )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip