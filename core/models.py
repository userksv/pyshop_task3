from django.db import models
from django.contrib.auth.models import User
from constance import config
import datetime
import uuid


class RefreshToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    uuid_token = models.UUIDField(primary_key=False, default=uuid.uuid4, editable=True, unique=True)
    created = models.DateTimeField(auto_now_add=True)
    
    def _get_refresh_expiry_constance(self):
        return config.REFRESH_TOKEN_EXPIRY_DAYS

    def is_expired(self):
        REFRESH_TOKEN_EXPIRY_DAYS = self._get_refresh_expiry_constance()
        return self.created > (datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS))

    def __str__(self) -> str:
        return f'{self.uuid_token}'