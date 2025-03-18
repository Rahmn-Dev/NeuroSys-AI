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