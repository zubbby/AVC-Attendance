from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from django.db.models import Count, Q
import uuid
import secrets
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.exceptions import ValidationError
import logging

def generate_session_token():
    return secrets.token_urlsafe(32)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    avc_id = models.CharField(max_length=20, unique=True, help_text="Unique identifier for the user (format: AVC-YYYY-XXXX)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"{self.user.get_full_name() or self.user.username} ({self.avc_id})"

    @property
    def full_name(self):
        return self.user.get_full_name() or self.user.username

    def clean(self):
        """Validate the AVC ID format"""
        if not self.avc_id.startswith('AVC-'):
            raise ValidationError({'avc_id': 'AVC ID must start with "AVC-"'})
        try:
            year = int(self.avc_id.split('-')[1])
            number = int(self.avc_id.split('-')[2])
            if not (2020 <= year <= timezone.now().year + 1):
                raise ValidationError({'avc_id': 'Invalid year in AVC ID'})
            if not (0 <= number <= 9999):
                raise ValidationError({'avc_id': 'Invalid number in AVC ID'})
        except (IndexError, ValueError):
            raise ValidationError({'avc_id': 'Invalid AVC ID format'})

def generate_avc_id():
    """Generate a unique AVC ID in the format AVC-YYYY-XXXX"""
    year = timezone.now().year
    max_attempts = 100  # Prevent infinite loops
    attempts = 0
    
    while attempts < max_attempts:
        random_num = secrets.randbelow(10000)  # Random number between 0 and 9999
        avc_id = f'AVC-{year}-{random_num:04d}'
        if not UserProfile.objects.filter(avc_id=avc_id).exists():
            return avc_id
        attempts += 1
    
    raise ValidationError("Could not generate a unique AVC ID after maximum attempts")

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Signal to automatically create a UserProfile when a new User is created"""
    if created:
        try:
            UserProfile.objects.get_or_create(
                user=instance,
                defaults={'avc_id': generate_avc_id()}
            )
        except Exception as e:
            # Log the error but don't prevent user creation
            logger = logging.getLogger(__name__)
            logger.error(f"Error creating user profile for {instance.username}: {str(e)}")
            raise ValidationError(f"Error creating user profile: {str(e)}")

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Signal to ensure UserProfile exists and is saved when User is saved"""
    try:
        if not hasattr(instance, 'profile'):
            # Create profile if it doesn't exist
            UserProfile.objects.create(
                user=instance,
                avc_id=generate_avc_id()
            )
        else:
            # Save existing profile
            instance.profile.save()
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error saving user profile for {instance.username}: {str(e)}")
        # Don't raise the exception to prevent user save from failing

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
