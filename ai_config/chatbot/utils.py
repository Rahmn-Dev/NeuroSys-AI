from django.contrib.auth.models import User
from .models import Profile  # Pastikan impor benar

def create_profiles_for_existing_users():
    """
    Create profiles for all existing users who don't have one.
    """
    for user in User.objects.all():
        profile, created = Profile.objects.get_or_create(user=user)
        if created:
            print(f"Created profile for user: {user.username}")