from django.apps import AppConfig


class AvcAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'avc_app'

    def ready(self):
        import avc_app.signals  # Import signals when app is ready
