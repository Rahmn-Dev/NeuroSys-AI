import uuid
from django.db import models

class ChatSession(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  # UUID sebagai primary key
    created_at = models.DateTimeField(auto_now_add=True)  # Waktu sesi chat dibuat
    updated_at = models.DateTimeField(auto_now=True)  # Waktu sesi chat terakhir diupdate

    def __str__(self):
        return f"ChatSession {self.id}"

class ChatMessage(models.Model):
    SENDER_CHOICES = [
        ('user', 'User'),
        ('ai', 'AI'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)  # UUID sebagai primary key
    session = models.ForeignKey(ChatSession, related_name='messages', on_delete=models.CASCADE)  # Relasi ke ChatSession
    sender = models.CharField(max_length=10, choices=SENDER_CHOICES)  # Sender: user atau AI
    message = models.TextField()  # Isi pesan
    created_at = models.DateTimeField(auto_now_add=True)  # Waktu pesan dikirim

    def __str__(self):
        return f"{self.sender}: {self.message[:50]}..."
    

from django.db import models
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.db.models.signals import post_save

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_active_session = models.BooleanField(default=False)  # Track active session
    image = models.ImageField(upload_to='profile_images/', blank=True, null=True)  # Profile image

    def __str__(self):
        return f"{self.user.username}'s Profile"

# Signal to create or update a profile when a User instance is created/updated
@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        # Create a profile for new users
        Profile.objects.create(user=instance)
    else:
        # Ensure the profile exists for existing users
        try:
            instance.profile.save()
        except Profile.DoesNotExist:
            Profile.objects.create(user=instance)

class SuricataLog(models.Model):
    timestamp = models.DateTimeField()
    message = models.TextField()
    severity = models.CharField(max_length=50, blank=True, null=True)
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    source_port = models.IntegerField(blank=True, null=True)  # Add this field
    destination_ip = models.GenericIPAddressField(blank=True, null=True)
    destination_port = models.IntegerField(blank=True, null=True)  # Add this field
    protocol = models.CharField(max_length=10, blank=True, null=True)
    classification = models.CharField(max_length=100, blank=True, null=True)
    priority = models.IntegerField(blank=True, null=True)

    def __str__(self):
        return f"{self.timestamp} - {self.message[:50]}"

    class Meta:
        ordering = ['-timestamp']
        