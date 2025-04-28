from rest_framework import serializers

from api.uca_exceptions import UCAPermissionError
from api.uca_helpers import UCAHelpers
from api.uca_models import UCAModel
from django.db import models
from django.apps import apps


class UCATokenObtainSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()


class UCATokenObtainRequestSerializer(serializers.Serializer):
    data = UCATokenObtainSerializer()
    flags = serializers.DictField(required=False, default={})


class UCATokenObtainResultSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    user = serializers.DictField()


class UCATokenObtainResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    messages = serializers.ListField(child=serializers.CharField(), default=[])
    result = UCATokenObtainResultSerializer()


class UCATokenRefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()


class UCATokenRefreshRequestSerializer(serializers.Serializer):
    data = UCATokenRefreshSerializer()
    flags = serializers.DictField(required=False, default={})


class UCATokenRefreshResultSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    user = serializers.DictField()
    permissions = serializers.ListField(child=serializers.CharField(), default=[])


class UCATokenRefreshResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    messages = serializers.ListField(child=serializers.CharField(), default=[])
    result = UCATokenRefreshResultSerializer()


class UCAListViewRequestSerializer(serializers.Serializer):
    filter = serializers.CharField(allow_blank=True, default="", required=False)
    order = serializers.ListField(
        child=serializers.CharField(), required=False, default=[]
    )
    flags = serializers.DictField(required=False, default={})

    class RequestPaginationSerializer(serializers.Serializer):
        limit = serializers.IntegerField(default=10)
        offset = serializers.IntegerField(default=0)

    pagination = RequestPaginationSerializer()


class UCAListViewResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    messages = serializers.ListField(child=serializers.CharField(), default=[])
    results = serializers.ListField(default=[], allow_empty=True)

    class ResponsePaginationSerializer(serializers.Serializer):
        limit = serializers.IntegerField()
        offset = serializers.IntegerField()
        page = serializers.IntegerField()
        pages = serializers.IntegerField()
        total = serializers.IntegerField()

    pagination = ResponsePaginationSerializer()


class UCAAddViewRequestSerializer(serializers.Serializer):
    data = serializers.DictField(required=True)
    flags = serializers.DictField(required=False, default={})


class UCAAddViewResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    messages = serializers.ListField(child=serializers.CharField(), default=[])
    result = serializers.DictField(default={})


class UCAGetViewRequestSerializer(serializers.Serializer):
    filter = serializers.CharField(allow_blank=True, default="", required=False)
    flags = serializers.DictField(required=False, default={})


class UCAGetViewResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    messages = serializers.ListField(child=serializers.CharField(), default=[])
    result = serializers.DictField(default={})


class UCAChangeViewRequestSerializer(serializers.Serializer):
    data = serializers.DictField(required=True)
    flags = serializers.DictField(required=False, default={})


class UCAChangeViewResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    messages = serializers.ListField(child=serializers.CharField(), default=[])
    result = serializers.DictField(default={})


class UCADeleteViewRequestSerializer(serializers.Serializer):
    filter = serializers.CharField(allow_blank=True, default="", required=False)
    flags = serializers.DictField(required=False, default={})


class UCADeleteViewResponseSerializer(serializers.Serializer):
    success = serializers.BooleanField()
    messages = serializers.ListField(child=serializers.CharField(), default=[])


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
                real_field_name = UCAHelpers.list_get(field_name.split("__"), 0, None)

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

    def create(self, validated_data, _save=True, **kwargs):
        request = self.context.get("request")
        request_user = request.user if request.user.is_authenticated else None

        # Check if the model has a created_by field
        if hasattr(self.Meta.model, "created_by"):
            # Check if the created_by field is not already set
            if not "created_by" in validated_data:
                # Set the created_by field to the current user
                validated_data.update({"created_by": request_user})

        obj = self.Meta.model(**validated_data)

        if _save:
            obj.save()

        return obj

    def update(self, instance, validated_data):
        request = self.context.get("request")
        request_user = request.user if request.user.is_authenticated else None

        # Check if the model has an updated_by field
        if hasattr(self.Meta.model, "updated_by"):
            # Check if the updated_by field is not already set
            if not "updated_by" in validated_data:
                # Set the updated_by field to the current user
                validated_data.update({"updated_by": request_user})

        return super().update(instance, validated_data)

    class Meta:
        fields = ["__model__"]
