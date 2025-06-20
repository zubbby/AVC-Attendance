from django.contrib import admin
from .models import Permission, Session, AttendanceRecord, IPBlacklist, UserProfile

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('created_at', 'updated_at')
    raw_id_fields = ('user',)

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

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'session', 'reason', 'status', 'created_at', 'approved_by', 'updated_at')
    list_filter = ('status', 'reason', 'created_at', 'updated_at')
    search_fields = ('user__username', 'user__email', 'user__first_name', 'user__last_name', 'explanation', 'admin_comment')
    readonly_fields = ('created_at', 'updated_at')
    raw_id_fields = ('user', 'session', 'approved_by')
    date_hierarchy = 'created_at'
    ordering = ('-created_at',)
    
    fieldsets = (
        ('User Information', {
            'fields': ('user',)
        }),
        ('Request Details', {
            'fields': ('session', 'reason', 'explanation')
        }),
        ('Administrative', {
            'fields': ('status', 'admin_comment', 'approved_by')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related(
            'user', 'user__profile', 'session', 'approved_by'
        )

admin.site.register(IPBlacklist)
