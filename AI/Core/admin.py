from django.contrib import admin
from .models import PasswordReset, LoginAttempt, RegistrationAttempt, ActivityLog, Contact

@admin.register(PasswordReset)
class PasswordResetAdmin(admin.ModelAdmin):
    list_display = ('user', 'reset_id', 'created_when')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('reset_id', 'created_when')

@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display = ('username', 'ip_address', 'attempt_time', 'was_successful')
    list_filter = ('was_successful', 'attempt_time')
    search_fields = ('username', 'ip_address')
    readonly_fields = ('attempt_time',)

@admin.register(RegistrationAttempt)
class RegistrationAttemptAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'attempt_time', 'was_successful')
    list_filter = ('was_successful', 'attempt_time')
    search_fields = ('ip_address',)
    readonly_fields = ('attempt_time',)

@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'activity_type', 'ip_address', 'created_at')  # Changed 'timestamp' to 'created_at'
    list_filter = ('activity_type', 'created_at')  # Changed 'timestamp' to 'created_at'
    search_fields = ('user__username', 'ip_address', 'details')
    readonly_fields = ('created_at',)  # Changed 'timestamp' to 'created_at'
    ordering = ('-created_at',)  # Optional: ensures consistent sorting with model Meta

    def has_add_permission(self, request):
        # Prevent manual addition of logs via admin
        return False

    def has_change_permission(self, request, obj=None):
        # Prevent manual editing of logs via admin
        return False

@admin.register(Contact)
class ContactAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'created_at', 'ip_address')
    search_fields = ('name', 'email', 'message')
    readonly_fields = ('created_at', 'ip_address')