from django.contrib.auth.models import UserManager
from django.db import models


class UCAModelManager(models.Manager):
    def property_annotate(self, queryset):
        return queryset

    def get_queryset(self):
        return self.property_annotate(super().get_queryset())

    def get_safe(self, *args, **kwargs):
        return self.get_queryset().filter(*args, **kwargs).first()


class UCAUserManager(UserManager):
    def property_annotate(self, queryset):
        return queryset

    def get_queryset(self):
        return self.property_annotate(super().get_queryset())

    def get_safe(self, *args, **kwargs):
        return self.get_queryset().filter(*args, **kwargs).first()
