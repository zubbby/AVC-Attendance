from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Count, Q
import uuid
import secrets

def generate_session_token():
    return secrets.token_urlsafe(32)

class Session(models.Model):
    name = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_sessions')
    is_active = models.BooleanField(default=True)
    allowed_users = models.ManyToManyField(User, related_name='allowed_sessions', help_text='Users who can mark attendance for this session')
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    session_token = models.CharField(max_length=64, unique=True, default=generate_session_token)

    def __str__(self):
        return f"{self.name} ({self.start_time.strftime('%Y-%m-%d %H:%M')})"

    @property
    def is_current(self):
        now = timezone.now()
        return self.start_time <= now <= self.end_time

    def save(self, *args, **kwargs):
        if not self.session_token:
            self.session_token = secrets.token_urlsafe(32)
        super().save(*args, **kwargs)

    def deactivate_if_expired(self):
        now = timezone.now()
        if self.is_active and self.end_time < now:
            self.is_active = False
            self.save(update_fields=["is_active"])

class AttendanceRecord(models.Model):
    session = models.ForeignKey(Session, on_delete=models.CASCADE, related_name='attendance_records')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='attendance_records')
    marked_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()

    class Meta:
        unique_together = ('session', 'user')  # One attendance record per user per session

    def __str__(self):
        return f"{self.user.username} - {self.session.name} ({self.marked_at.strftime('%Y-%m-%d %H:%M')})"

    @property
    def is_valid(self):
        # Valid if marked during the session and IP is not blacklisted
        session_valid = self.session.start_time <= self.marked_at <= self.session.end_time
        ip_valid = not IPBlacklist.objects.filter(ip_address=self.ip_address, is_active=True).exists()
        return session_valid and ip_valid

class IPBlacklist(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    blocked_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Blocked IP: {self.ip_address} - {'Active' if self.is_active else 'Expired'}"

class Permission(models.Model):
    REASON_CHOICES = [
        ('late', 'Late'),
        ('absent', 'Absent'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='permissions')
    session = models.ForeignKey(Session, on_delete=models.CASCADE, related_name='permissions')
    reason = models.CharField(max_length=10, choices=REASON_CHOICES)
    explanation = models.TextField(help_text="Please provide details about your request")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_permissions')
    approved_at = models.DateTimeField(null=True, blank=True)
    admin_comment = models.TextField(blank=True, null=True, help_text="Admin's response to the permission request")

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username} - {self.session.name} ({self.get_reason_display()})"

    def save(self, *args, **kwargs):
        if self.status == 'approved' and not self.approved_at:
            self.approved_at = timezone.now()
        super().save(*args, **kwargs)

    @property
    def affects_attendance(self):
        """Returns True if this permission should affect attendance count"""
        return self.status == 'approved' and self.reason == 'absent'
