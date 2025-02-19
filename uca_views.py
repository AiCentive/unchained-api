from django.conf import settings
from django.db import transaction
from django.db.models import Q
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .uca_context import UCAContext
from .uca_exceptions import (
    UCAAuthInvalid,
    UCAAuthRefreshTokenInvalid,
    UCAFilterWrongFormat,
    UCAPaginationNotProvided,
    UCAOrderNotProvided,
    UCAObjectPermissionDenied,
    UCAObjectPermissionCheckError,
    UCASerializerInvalid,
    UCADataIdNotProvided,
    UCARequestMethodNotAllowed,
    UCAEmptyRequestError,
)
from .uca_helpers import UCAHelpers
from .uca_jwt import decode_jwt, create_jwt
from .uca_paginator import UCAPaginator


class UCAView(APIView):
    """
    A base API view that handles context, request data processing, and response formatting.
    """

    action_name = None

    transactional = True
    encryption = False

    context = {}
    request_content = {}
    request_data = {}
    request_flags = {}
    request_filter = None
    request_order = None
    request_order_required = False
    request_pagination = None
    request_pagination_required = False

    model_class = None
    user_serializer = None
    return_serializer_class = None

    should_check_obj_permission = True
    should_check_serializer_obj_permission = True

    def add_user_to_context(self):
        """
        Adds the authenticated user's data to the context if available.
        """
        user = self.request.user

        # Only add the user to the context if authenticated and a serializer is provided
        if user and user.is_authenticated and self.user_serializer:
            self.context["user"] = self.user_serializer(instance=user).data

    def get_return_serializer_class(self):
        return self.return_serializer_class

    def check_object_permission(self, obj, action, should_raise=True):
        exc = None

        if not self.should_check_obj_permission:
            return True

        if action == "view":
            if self.should_check_obj_permission and not obj.check_view_perm(
                self.request
            ):
                exc = UCAObjectPermissionDenied()
        elif action == "add":
            if self.should_check_obj_permission and not obj.check_add_perm(
                self.request
            ):
                exc = UCAObjectPermissionDenied()
        elif action == "change":
            if self.should_check_obj_permission and not obj.check_change_perm(
                self.request
            ):
                exc = UCAObjectPermissionDenied()
        elif action == "delete":
            if self.should_check_obj_permission and not obj.check_delete_perm(
                self.request
            ):
                exc = UCAObjectPermissionDenied()
        else:
            print(f"Unknown action: {action}")
            exc = UCAObjectPermissionCheckError()

        if should_raise and exc:
            raise exc

        return exc is None

    def get_request_data(self, key, exception=None, eval_expr=False):
        """
        Retrieves and optionally evaluates request content for the given key.
        Raises an exception if the key is not found and an exception is provided.
        """
        value = self.request_content.get(key, None)
        if value is None and exception:
            raise exception
        return UCAHelpers.eval_expr(value) if eval_expr and value else value

    def get_request_content(self):
        """
        Extracts the content, data, and flags from the request based on the HTTP method.
        Raises an error if the request is empty or unsupported.
        """
        if not self.request:
            raise UCAEmptyRequestError()

        method_handlers = {
            "GET": self.request.GET,
            "POST": self.request.data,
            "PUT": self.request.data,
            "DELETE": self.request.data,
            "PATCH": self.request.data,
        }

        if self.request.method not in method_handlers:
            raise UCARequestMethodNotAllowed()

        self.request_content = method_handlers[self.request.method]

        self.request_data = self.get_request_data("data")
        self.request_flags = self.get_request_data("flags")
        self.request_filter = self.get_request_data("filter", eval_expr=True)
        self.request_order = self.get_request_data(
            "order",
            UCAOrderNotProvided() if self.request_order_required else None,
        )
        self.request_pagination = self.get_request_data(
            "pagination",
            UCAPaginationNotProvided() if self.request_pagination_required else None,
        )

    def get_queryset(self):
        """
        Placeholder for subclasses to implement their own queryset logic.
        """
        raise NotImplementedError()

    def annotate_queryset(self, queryset):
        """
        Placeholder for subclasses to implement their own queryset annotation logic.
        """
        return queryset

    def handler(self):
        """
        Placeholder for subclasses to implement their main request handling logic.
        """
        raise NotImplementedError()

    def respond(self, http_code=status.HTTP_200_OK):
        """
        Formats and returns the API response with optional encryption.
        """
        response_data = (
            UCAHelpers.encrypt_context(self.context)
            if self.encryption
            else self.context
        )
        return Response(response_data, status=http_code)


class CustomV2TokenObtain(UCAView):
    """
    Handles obtaining access and refresh tokens for a user.
    """

    context = UCAContext.list()
    access_token_expiry = (
        settings.UCA_JWT_ACCESS_TOKEN_EXPIRY
        if hasattr(settings, "UCA_JWT_ACCESS_TOKEN_EXPIRY")
        else 5
    )  # in minutes
    refresh_token_expiry = (
        settings.UCA_JWT_REFRESH_TOKEN_EXPIRY
        if hasattr(settings, "UCA_JWT_REFRESH_TOKEN_EXPIRY")
        else 60 * 24 * 7
    )  # in minutes
    refresh_token_expiry_remembered = (
        settings.UCA_JWT_REFRESH_TOKEN_REMEMBERED_EXPIRY
        if hasattr(settings, "UCA_JWT_REFRESH_TOKEN_REMEMBERED_EXPIRY")
        else 60 * 24 * 7 * 30
    )  # in minutes

    def generate_token_payloads(self, user, remember=False):
        """
        Generates payloads for access and refresh tokens based on user data.
        """
        shared_payload = {
            "user_id": str(user.id),
            "user_agent": UCAHelpers.get_client_user_agent(self.request),
            "user_ip": UCAHelpers.get_client_ip(self.request),
        }

        access_token_payload = shared_payload

        refresh_token_payload = {
            **shared_payload,
            "is_refresh_token": True,
            "remember": remember,
        }

        return access_token_payload, refresh_token_payload

    @staticmethod
    def __generate_jwt_token(payload, expiry_minutes):
        """
        Generates a JWT token with the specified payload and expiry.
        """
        return create_jwt(payload, expiry_minutes)

    def _auth_method(self, username, password):
        """
        Authenticates a user using Django's built-in authentication system.
        """
        from django.contrib.auth import authenticate

        return authenticate(username=username, password=password), None

    def handler(self):
        """
        Handles the token generation process after authenticating the user.
        """
        username = self.request_data.get("username")
        password = self.request_data.get("password")
        remember = self.request_data.get("remember", False) == True
        user, _ = self._auth_method(username, password)

        if not user:
            raise UCAAuthInvalid()

        access_token_payload, refresh_token_payload = self.generate_token_payloads(
            user,
            remember=remember,
        )
        access_token = self.__generate_jwt_token(
            access_token_payload, self.access_token_expiry
        )
        refresh_token = self.__generate_jwt_token(
            refresh_token_payload,
            (
                self.refresh_token_expiry
                if not remember
                else self.refresh_token_expiry_remembered
            ),
        )

        results = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        if self.user_serializer:
            results["user"] = self.user_serializer(instance=user).data

        self.context["results"] = results

    def process(self):
        """
        Processes the request by extracting data, handling the logic, and returning a response.
        """
        self.handler()
        self.context.update({"success": True, "status": status.HTTP_200_OK})
        return self.respond(status.HTTP_200_OK)

    def post(self, *args, **kwargs):
        """
        Handles POST requests and wraps the process in a transaction if necessary.
        """
        self.get_request_content()

        if self.transactional:
            with transaction.atomic():
                return self.process()
        return self.process()


class CustomV2TokenRefresh(UCAView):
    """
    Handles refreshing an access token using a valid refresh token.
    """

    context = UCAContext.list()
    access_token_expiry = (
        settings.UCA_JWT_ACCESS_TOKEN_EXPIRY
        if hasattr(settings, "UCA_JWT_ACCESS_TOKEN_EXPIRY")
        else 5
    )  # in minutes
    refresh_token_expiry = (
        settings.UCA_JWT_REFRESH_TOKEN_EXPIRY
        if hasattr(settings, "UCA_JWT_REFRESH_TOKEN_EXPIRY")
        else 60 * 24 * 7
    )  # in minutes
    refresh_token_expiry_remembered = (
        settings.UCA_JWT_REFRESH_TOKEN_REMEMBERED_EXPIRY
        if hasattr(settings, "UCA_JWT_REFRESH_TOKEN_REMEMBERED_EXPIRY")
        else 60 * 24 * 7 * 30
    )  # in minutes

    def generate_token_payloads(self, user, refresh_token_data):
        """
        Generates payloads for access and refresh tokens based on user data.
        """
        shared_payload = {
            "user_id": str(user.id),
            "user_agent": UCAHelpers.get_client_user_agent(self.request),
            "user_ip": UCAHelpers.get_client_ip(self.request),
        }

        access_token_payload = shared_payload

        refresh_token_payload = {
            **shared_payload,
            "is_refresh_token": True,
            "remember": refresh_token_data.get("remember") == True,
        }

        return access_token_payload, refresh_token_payload

    @staticmethod
    def __generate_jwt_token(payload, expiry_minutes):
        """
        Generates a JWT token with the specified payload and expiry.
        """
        return create_jwt(payload, expiry_minutes)

    def validate_refresh_token(self, refresh_token):
        """
        Validates the refresh token and returns the associated user if valid.
        """
        if not refresh_token.get("is_refresh_token"):
            raise UCAAuthRefreshTokenInvalid("Not a refresh token")

        user_id = refresh_token.get("user_id")
        if not user_id:
            raise UCAAuthRefreshTokenInvalid("User ID not found in refresh token")

        user = self.model_class.objects.get(id=user_id)

        if not user.is_active:
            return user, False

        return user, True

    def handler(self):
        """
        Handles the token refresh process by validating the refresh token and generating new tokens.
        """
        encoded_refresh_token = self.request_data.get("refresh_token")
        if not encoded_refresh_token:
            raise UCAAuthInvalid()

        refresh_token_data = decode_jwt(encoded_refresh_token)

        is_refresh_token = refresh_token_data.get("is_refresh_token")
        is_refresh_token_remember = "remember" in refresh_token_data

        if not is_refresh_token:
            raise UCAAuthRefreshTokenInvalid("Not a refresh token")

        user, is_refresh_token_valid = self.validate_refresh_token(refresh_token_data)
        if not user or not is_refresh_token_valid:
            raise UCAAuthRefreshTokenInvalid()

        access_token_payload, refresh_token_payload = self.generate_token_payloads(
            user, refresh_token_data
        )

        access_token = self.__generate_jwt_token(
            access_token_payload,
            expiry_minutes=self.access_token_expiry,
        )
        refresh_token = self.__generate_jwt_token(
            refresh_token_payload,
            expiry_minutes=(
                self.refresh_token_expiry
                if not is_refresh_token_remember
                else self.refresh_token_expiry_remembered
            ),
        )

        results = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        if self.user_serializer:
            results["user"] = self.user_serializer(instance=user).data

        self.context["results"] = results

    def process(self):
        """
        Processes the request by extracting data, handling the logic, and returning a response.
        """
        self.handler()
        self.context.update({"success": True, "status": status.HTTP_200_OK})
        return self.respond(status.HTTP_200_OK)

    def post(self, *args, **kwargs):
        """
        Handles POST requests and wraps the process in a transaction if necessary.
        """
        self.get_request_content()

        if self.transactional:
            with transaction.atomic():
                return self.process()
        return self.process()


class UCAListView(UCAView):
    context = UCAContext.list()
    action_name = "view"

    distinct_objects = False
    request_order_required = True
    request_pagination_required = True

    def get_queryset(self):
        """
        Constructs and returns the queryset with optional filtering, annotation, and ordering.
        """
        queryset = self.model_class.objects
        if self.request_filter:
            if not isinstance(self.request_filter, Q):
                raise UCAFilterWrongFormat()
            queryset = queryset.filter(self.request_filter)

        if self.distinct_objects:
            queryset = queryset.distinct()

        queryset = self.annotate_queryset(queryset)
        return queryset.order_by(*self.request_order or [])

    def hook_before_serializer(self, result_set):
        """
        Placeholder for subclasses to implement pre-serialization logic.
        """
        pass

    def hook_after_serializer(self, result_set):
        """
        Placeholder for subclasses to implement post-serialization logic.
        """
        pass

    def handler(self):
        """
        Handles the core logic of retrieving, paginating, and serializing data.
        """
        queryset = self.get_queryset()

        paginator = UCAPaginator(
            self.request_pagination, distinct=self.distinct_objects
        )
        result_set = paginator.paginate(
            objects=queryset,
            request=self.request,
            check_object_permission=self.should_check_obj_permission,
        )

        paginator.update_context(self.context)
        self.hook_before_serializer(result_set)

        result_set = [
            self.get_return_serializer_class()(
                instance=result,
                context={
                    "request": self.request,
                    "view": self,
                    "check_field_permission": self.should_check_serializer_obj_permission,
                    "action": "view",
                },
            ).data
            for result in result_set
        ]

        self.hook_after_serializer(result_set)
        self.context.update({"results": result_set})

    def process(self):
        """
        Processes the request by extracting data, executing the handler, and preparing the response.
        """
        self.handler()
        self.add_user_to_context()
        self.context.update({"success": True, "status": status.HTTP_200_OK})
        return self.respond(status.HTTP_200_OK)

    def post(self, *args, **kwargs):
        """
        Handles POST requests, optionally wrapping the process in a transaction.
        """
        self.get_request_content()

        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


class UCAGetView(UCAView):
    context = UCAContext.get()
    action_name = "view"

    model_class = None

    def get_queryset(self):
        """
        Constructs and returns the queryset with optional filtering, annotation, and ordering.
        """
        queryset = self.model_class.objects
        if not isinstance(self.request_filter, Q):
            raise UCAFilterWrongFormat()

        queryset = self.annotate_queryset(queryset).get(self.request_filter)

        return queryset

    def hook_before_serializer(self, obj):
        """
        Placeholder for subclasses to implement pre-serialization logic.
        """
        pass

    def hook_after_serializer(self, object, serialized_object):
        """
        Placeholder for subclasses to implement post-serialization logic.
        """
        pass

    def handler(self):
        obj = self.get_queryset()
        self.check_object_permission(obj, self.action_name)

        self.hook_before_serializer(obj)
        serialized_obj = self.get_return_serializer_class()(
            obj,
            context={
                "request": self.request,
                "view": self,
                "check_field_permission": self.should_check_serializer_obj_permission,
                "action": self.action_name,
            },
        ).data
        self.hook_after_serializer(obj, serialized_obj)

        self.context.update({"result": serialized_obj})

    def process(self):
        """
        Processes the request by extracting data, executing the handler, and preparing the response.
        """
        self.handler()
        self.add_user_to_context()
        self.context.update({"success": True, "status": status.HTTP_200_OK})
        return self.respond(status.HTTP_200_OK)

    def post(self, *args, **kwargs):
        """
        Handles POST requests, optionally wrapping the process in a transaction.
        """
        self.get_request_content()

        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


class UCAAddView(UCAView):
    context = UCAContext.create()
    action_name = "add"

    model_class = None
    serializer_class = None

    def get_serializer_class(self):
        return self.serializer_class

    def hook_before_creation(self, tmp_obj):
        """
        Placeholder for subclasses to implement pre-creation logic.
        """
        pass

    def hook_after_creation(self, obj):
        """
        Placeholder for subclasses to implement post-creation logic.
        """
        pass

    def handler(self):
        serializer = self.get_serializer_class()(
            data=self.request_data,
            context={
                "request": self.request,
                "view": self,
                "check_field_permission": self.should_check_serializer_obj_permission,
                "action": self.action_name,
            },
        )

        if not serializer.is_valid():
            # TODO: Make the serializer errors available in the context
            # self.handle_invalid_serializer(serializer)
            raise UCASerializerInvalid(serializer.errors)

        tmp_object = self.model_class(**serializer.validated_data)
        self.hook_before_creation(tmp_object)

        self.check_object_permission(tmp_object, self.action_name)

        tmp_object.save()

        self.hook_after_creation(tmp_object)

        self.context.update(
            {
                "result": self.get_return_serializer_class()(
                    instance=tmp_object,
                    context={
                        "request": self.request,
                        "view": self,
                        "check_field_permission": self.should_check_serializer_obj_permission,
                        "action": self.action_name,
                    },
                ).data
            }
        )

    def process(self):
        """
        Processes the request by extracting data, executing the handler, and preparing the response.
        """
        self.handler()
        self.add_user_to_context()
        self.context.update({"success": True, "status": status.HTTP_201_CREATED})
        return self.respond(status.HTTP_201_CREATED)

    def put(self, *args, **kwargs):
        """
        Handles POST requests, optionally wrapping the process in a transaction.
        """
        self.get_request_content()

        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


class UCAChangeView(UCAView):
    context = UCAContext.update()
    action_name = "change"

    model_class = None
    serializer_class = None

    def get_serializer_class(self):
        return self.serializer_class

    def get_queryset(self):
        """
        Constructs and returns the queryset with optional filtering, annotation, and ordering.
        """
        id = self.request_data.get("id")

        if not id:
            raise UCADataIdNotProvided()

        return self.model_class.objects.get(id=id)

    def hook_before_update(self, obj):
        """
        Placeholder for subclasses to implement pre-update logic.
        """
        pass

    def hook_after_update(self, obj):
        """
        Placeholder for subclasses to implement post-update logic.
        """
        pass

    def handler(self):
        obj = self.get_queryset()
        self.check_object_permission(obj, self.action_name)

        self.hook_before_update(obj)

        serializer = self.get_serializer_class()(
            instance=obj,
            data=self.request_data,
            partial=True,
            context={
                "request": self.request,
                "view": self,
                "check_field_permission": self.should_check_serializer_obj_permission,
                "action": self.action_name,
            },
        )

        if not serializer.is_valid():
            # TODO: Make the serializer errors available in the context
            # self.handle_invalid_serializer(serializer)
            raise UCASerializerInvalid(serializer.errors)

        updated_object = serializer.save()

        self.hook_after_update(updated_object)

        self.context.update(
            {
                "result": self.get_return_serializer_class()(
                    instance=updated_object,
                    context={
                        "request": self.request,
                        "view": self,
                        "check_field_permission": self.should_check_serializer_obj_permission,
                        "action": self.action_name,
                    },
                ).data
            }
        )

    def process(self):
        """
        Processes the request by extracting data, executing the handler, and preparing the response.
        """
        self.handler()
        self.add_user_to_context()
        self.context.update({"success": True, "status": status.HTTP_200_OK})
        return self.respond(status.HTTP_200_OK)

    def patch(self, *args, **kwargs):
        """
        Handles PATCH requests, optionally wrapping the process in a transaction.
        """
        self.get_request_content()

        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()


class UCADeleteView(UCAView):
    context = UCAContext.remove()
    action_name = "delete"

    model_class = None

    def get_queryset(self):
        """
        Constructs and returns the queryset with optional filtering, annotation, and ordering.
        """
        id = self.request_data.get("id")

        if not id:
            raise UCADataIdNotProvided()

        return self.model_class.objects.get(id=id)

    def hook_before_deletion(self, obj):
        """
        Placeholder for subclasses to implement pre-deletion logic.
        """
        pass

    def hook_after_deletion(self):
        """
        Placeholder for subclasses to implement post-deletion logic.
        """
        pass

    def handler(self):
        obj = self.get_queryset()
        self.check_object_permission(obj, self.action_name)

        self.hook_before_deletion(obj)

        obj.delete()

        self.hook_after_deletion()

    def process(self):
        """
        Processes the request by extracting data, executing the handler, and preparing the response.
        """
        self.handler()
        self.add_user_to_context()
        self.context.update({"success": True, "status": status.HTTP_200_OK})
        return self.respond(status.HTTP_200_OK)

    def post(self, *args, **kwargs):
        """
        Handles POST requests, optionally wrapping the process in a transaction.
        """
        self.get_request_content()

        if self.transactional:
            with transaction.atomic():
                return self.process()

        return self.process()
