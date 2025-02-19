import uuid

from django.contrib.auth.models import AbstractUser
from django.db import models
from .uca_manager import UCAModelManager, UCAUserManager


class UCAModel(models.Model):
    objects = UCAModelManager()

    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True
    )
    is_active = models.BooleanField(default=True)

    class Meta:
        base_manager_name = "objects"
        abstract = True

    @property
    def _reference_hash(self):
        return f"{self.__class__.__name__}:{self.id}"

    def check_obj_perm(self, request):
        return False

    def check_add_perm(self, request):
        return False

    def check_view_perm(self, request):
        return False

    def check_change_perm(self, request):
        return False

    def check_delete_perm(self, request):
        return False

    def check_export_perm(self, request):
        return False


class UCAAbstractUser(AbstractUser):
    objects = UCAUserManager()
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, unique=True
    )

    full_name = models.CharField(max_length=512, default="N/A")

    email = models.EmailField(
        blank=True,
        unique=True,
    )

    def __str__(self):
        return f"[{self.id}] {self.username} ({self.full_name})"

    class Meta:
        base_manager_name = "objects"
        abstract = True

    def save(self, *args, **kwargs):
        self.full_name = f"{self.first_name} {self.last_name}"
        super().save(*args, **kwargs)
