from django.contrib import admin
from .models import Session, AttendanceRecord
from .user_profile import UserProfile

@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_by', 'start_time', 'end_time', 'is_active', 'is_current')
    list_filter = ('is_active', 'created_by', 'start_time')
    search_fields = ('name', 'created_by__username')
    filter_horizontal = ('allowed_users',)  # Makes it easier to add/remove allowed users
    readonly_fields = ('created_at',)

    def is_current(self, obj):
        return obj.is_current
    is_current.boolean = True
    is_current.short_description = 'Current'

@admin.register(AttendanceRecord)
class AttendanceRecordAdmin(admin.ModelAdmin):
    list_display = ('user', 'session', 'marked_at', 'ip_address')
    list_filter = ('session', 'user', 'marked_at')
    search_fields = ('user__username', 'session__name', 'ip_address')
    readonly_fields = ('marked_at',)

admin.site.register(UserProfile)
