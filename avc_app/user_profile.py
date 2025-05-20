from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    avc_id = models.CharField(max_length=7, unique=True, editable=False)  # Format: AVC001
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.avc_id} - {self.user.username}"

    @classmethod
    def generate_avc_id(cls):
        # Get the last used ID
        last_profile = cls.objects.order_by('-avc_id').first()
        if last_profile:
            # Extract the number part and increment
            last_num = int(last_profile.avc_id[3:])
            new_num = last_num + 1
        else:
            new_num = 1
        # Format as AVC001, AVC002, etc.
        return f"AVC{new_num:03d}"

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(
            user=instance,
            avc_id=UserProfile.generate_avc_id()
        )

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save() 