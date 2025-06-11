from django.db.models.signals import m2m_changed
from django.dispatch import receiver
from django.utils import timezone
from .models import Session, AttendanceRecord

@receiver(m2m_changed, sender=Session.allowed_users.through)
def create_attendance_records(sender, instance, action, pk_set, **kwargs):
    """
    Signal handler to automatically create attendance records when users are added to a session.
    This is triggered when the allowed_users field of a Session is modified.
    """
    if action == "post_add" and instance.is_active and instance.is_current:
        # Get the current time
        now = timezone.now()
        
        # Only create attendance records if the session is active and current
        if instance.start_time <= now <= instance.end_time:
            # Create attendance records for newly added users
            for user_id in pk_set:
                # Check if an attendance record already exists
                if not AttendanceRecord.objects.filter(session=instance, user_id=user_id).exists():
                    # Create the attendance record
                    AttendanceRecord.objects.create(
                        session=instance,
                        user_id=user_id,
                        ip_address='127.0.0.1',  # Default to localhost
                        user_agent='System Generated'  # Default user agent
                    ) 
