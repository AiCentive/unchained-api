from rest_framework import serializers

from api.uca_exceptions import UCAPermissionError
from api.uca_helpers import UACHelpers
from api.uca_models import UCAModel
from django.db import models
from django.apps import apps


class UCAModelSerializer(serializers.ModelSerializer):
    __model__ = serializers.SerializerMethodField("get__model__")

    def __init__(self, *args, **kwargs):

        # Fix to allow model to be a string. This is needed to prevent circular imports.
        if type(self.Meta.model) == str:
            self.Meta.model = apps.get_model(self.Meta.model)

        super(UCAModelSerializer, self).__init__(*args, **kwargs)

    def get__model__(self, obj):
        return self.Meta.model.__name__

    @classmethod
    def get_accessible_fields(cls, request, check_field_permission=False):
        res = [*cls.Meta.fields]

        if not check_field_permission:
            return res

        if not request:
            return res

        current_user = request.user
        if not current_user:
            return res

        accessible_fields = []

        for i, field_name in enumerate(res):
            real_field_name = field_name

            # TODO: SECURITY_NOTE: Private fields are always accessible.
            if field_name.startswith("__"):
                accessible_fields.append(field_name)
                continue

            if "__" in field_name:
                real_field_name = UACHelpers.list_get(field_name.split("__"), 0, None)

            if not real_field_name:
                continue

            if current_user.has_perm(
                "%s.view_%s_%s"
                % (
                    cls.Meta.model._meta.app_label,
                    cls.Meta.model._meta.model_name,
                    real_field_name,
                )
            ):
                accessible_fields.append(field_name)

        return accessible_fields

    def to_representation(self, request_data):
        ret = super(UCAModelSerializer, self).to_representation(request_data)
        if not self.context.get("check_field_permission", False):
            return ret

        accessible_fields = self.__class__.get_accessible_fields(
            self.context.get("request"),
            self.context.get("check_field_permission", False),
        )

        for field_name, field_value in sorted(ret.items()):
            if field_name not in accessible_fields:
                ret.pop(field_name)

        return ret

    def run_validators(self, value):
        """
        Checking object permission on related fields.
        """
        for field_name, field_value in value.items():
            if isinstance(field_value, (UCAModel, models.Model)):
                if self.context.get(
                    "check_field_permission", False
                ) and not field_value.check_view_perm(self.context.get("request")):
                    raise UCAPermissionError()

        super().run_validators(value)

    class Meta:
        fields = ["__model__"]
