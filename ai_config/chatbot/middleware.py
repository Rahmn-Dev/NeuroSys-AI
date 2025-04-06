from django.shortcuts import redirect
from django.urls import reverse

class EnforceActiveSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Bypass middleware untuk halaman login, setup 2FA, dan logout
        if (
            request.path.startswith(reverse('login')) or
            request.path.startswith(reverse('setup_2fa')) or
            request.path.startswith(reverse('logout'))
        ):
            return self.get_response(request)

        # Periksa apakah pengguna sudah login dan sesi aktif
        if request.user.is_authenticated:
            if not getattr(request.user.profile, 'is_active_session', False):
                # Redirect to setup 2FA if the session is not active
                return redirect('setup_2fa')

        return self.get_response(request)