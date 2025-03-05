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
from .uca_serializers import (
    UCAListViewRequestSerializer,
    UCAListViewResponseSerializer,
    UCAAddViewRequestSerializer,
    UCAAddViewResponseSerializer,
    UCAGetViewRequestSerializer,
    UCAGetViewResponseSerializer,
    UCAChangeViewRequestSerializer,
    UCAChangeViewResponseSerializer,
    UCADeleteViewRequestSerializer,
    UCADeleteViewResponseSerializer,
    UCATokenObtainRequestSerializer,
    UCATokenObtainResponseSerializer,
    UCATokenRefreshRequestSerializer,
    UCATokenRefreshResponseSerializer,
)


# UCAView serves as a base API view that provides common functionality for processing
# HTTP requests, managing request data, performing permission checks, and formatting responses.
# It is designed to be subclassed with concrete implementations for specific resource handling.
class UCAView(APIView):
    """
    A base API view that handles context initialization, request data processing, permission checks,
    and response formatting. Subclasses should implement resource-specific logic by overriding
    get_queryset(), annotate_queryset(), and handler() methods.
    """

    # Action name can be used to define the current operation or behavior of the view.
    action_name = None

    # Determines whether the request should be treated as transactional.
    transactional = True

    # Containers for various data extracted from the request.
    context = {}  # Response context to be passed to serializers.
    request_content = {}  # Raw content extracted from the HTTP request.
    request_data = {}  # Processed request data after validation.
    request_flags = {}  # Additional flags provided in the request.
    request_filter = None  # Filtering criteria extracted from the request.
    request_order = None  # Ordering criteria extracted from the request.
    request_order_required = False  # Flag to indicate if ordering is mandatory.
    request_pagination = None  # Pagination parameters extracted from the request.
    request_pagination_required = False  # Flag to indicate if pagination is mandatory.

    # Model and serializer classes to be defined in subclasses.
    model_class = None
    request_serializer_class = None
    base_response_serializer_class = None
    user_serializer = None
    model_return_serializer_class = None

    # Flags to control whether permission checks should be enforced on objects and serializer objects.
    should_check_obj_permission = True
    should_check_serializer_obj_permission = True

    def add_user_to_context(self):
        """
        Adds the authenticated user's serialized data to the view context.

        This method checks if the user exists and is authenticated. If a user_serializer
        is defined, it serializes the user instance and adds it to the context dictionary.
        """
        user = self.request.user

        # Only add the user to the context if authenticated and a serializer is provided.
        if user and user.is_authenticated and self.user_serializer:
            self.context["user"] = self.user_serializer(instance=user).data

    @classmethod
    def get_response_serializer_class(cls, view=None):
        """
        Returns the serializer class used for formatting the response data.

        This class method can be overridden to provide a different serializer for the response,
        possibly based on the view instance or context.

        :param view: (Optional) A view instance that may influence serializer selection.
        :return: The serializer class for the response.
        """
        return cls.base_response_serializer_class

    @classmethod
    def get_model_return_serializer_class(cls, view=None):
        """
        Returns the serializer class used for serializing the model data to be returned.

        This class method can be overridden to change the serializer responsible for converting
        model instances into a response-friendly format.

        :param view: (Optional) A view instance that may influence serializer selection.
        :return: The serializer class for model data serialization.
        """
        return cls.model_return_serializer_class

    def check_object_permission(self, obj, action, should_raise=True):
        """
        Checks whether the current request has the necessary permissions to perform an action on an object.

        The method inspects the 'action' parameter to determine which permission check to perform.
        It then calls the corresponding method (e.g., check_view_perm, check_add_perm, etc.) on the object.
        If the permission check fails and should_raise is True, the corresponding permission exception is raised.

        :param obj: The model instance on which permission is being checked.
        :param action: A string representing the action (e.g., "view", "add", "change", "delete").
        :param should_raise: Boolean indicating whether to raise an exception on permission failure.
        :return: True if permission is granted; otherwise, returns False or raises an exception.
        """
        exc = None

        # If permission checks are disabled, assume permission is granted.
        if not self.should_check_obj_permission:
            return True

        # Perform the corresponding permission check based on the action.
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
            # Log or handle unknown actions appropriately.
            print(f"Unknown action: {action}")
            exc = UCAObjectPermissionCheckError()

        # Raise an exception if the check fails and should_raise is True.
        if should_raise and exc:
            raise exc

        return exc is not None

    def get_request_data(self, key, exception=None, eval_expr=False):
        """
        Retrieves a value from the processed request content using the specified key.

        If the key is missing and an exception is provided, it will raise that exception.
        Optionally, the value can be evaluated as an expression if 'eval_expr' is True.

        :param key: The key to retrieve from the request content.
        :param exception: An optional exception to raise if the key is missing.
        :param eval_expr: Boolean flag to indicate whether to evaluate the value as an expression.
        :return: The retrieved value (possibly evaluated) or raises the provided exception.
        """
        value = self.request_content.get(key, None)
        if value is None and exception:
            raise exception
        return UCAHelpers.eval_expr(value) if eval_expr and value else value

    def get_request_content(self):
        """
        Extracts and validates the content of the request based on the HTTP method.

        The method supports various HTTP methods (GET, POST, PUT, DELETE, PATCH) by mapping
        them to the appropriate attribute of the request. After extraction, the content is
        validated using the request serializer. On successful validation, the method extracts
        and stores filtering, ordering, pagination, flags, and data into dedicated attributes.

        :raises UCAEmptyRequestError: If the request object is not present.
        :raises UCARequestMethodNotAllowed: If the HTTP method is unsupported.
        :raises UCASerializerInvalid: If the request serializer fails validation.
        """
        if not self.request:
            raise UCAEmptyRequestError()

        # Mapping of HTTP methods to their corresponding data sources in the request.
        method_handlers = {
            "GET": self.request.GET,
            "POST": self.request.data,
            "PUT": self.request.data,
            "DELETE": self.request.data,
            "PATCH": self.request.data,
        }

        # Check if the method is supported; raise an error if not.
        if self.request.method not in method_handlers:
            raise UCARequestMethodNotAllowed()

        # Extract the raw request content.
        self.request_content = method_handlers[self.request.method]

        # Validate the request content using the provided request serializer.
        serializer = self.request_serializer_class(data=self.request_content)
        if not serializer.is_valid():
            raise UCASerializerInvalid(serializer.errors)

        # Extract validated data and evaluate expressions if necessary.
        self.request_filter = UCAHelpers.eval_expr(
            serializer.validated_data.get("filter")
        )
        self.request_order = serializer.validated_data.get("order")
        self.request_pagination = serializer.validated_data.get("pagination")
        self.request_flags = serializer.validated_data.get("flags")
        self.request_data = serializer.validated_data.get("data")

    def get_queryset(self):
        """
        Provides a base method for obtaining the queryset for the current request.

        Subclasses are expected to override this method to implement custom logic for
        retrieving and filtering the queryset from the database.

        :raises NotImplementedError: If the subclass does not implement this method.
        """
        raise NotImplementedError()

    def annotate_queryset(self, queryset):
        """
        Provides a hook for subclasses to perform additional annotations on the queryset.

        This method can be overridden to add extra computed fields or perform complex database
        annotations prior to further processing.

        :param queryset: The initial queryset retrieved from get_queryset().
        :return: The modified queryset after annotations (default is unchanged).
        """
        return queryset

    def handler(self):
        """
        Main request handling function that should be implemented by subclasses.

        This method is intended to encapsulate the core business logic of the API endpoint,
        such as processing the request, performing database operations, and updating the context.

        :raises NotImplementedError: If not overridden in the subclass.
        """
        raise NotImplementedError()

    def respond(self, http_code=status.HTTP_200_OK):
        """
        Prepares and returns an HTTP response using the current context and a specified status code.

        The method uses a response serializer (obtained via the class method) to format the response.
        A TODO is noted regarding serializer validation that might need to be addressed in the future.

        :param http_code: The HTTP status code to return (default is 200 OK).
        :return: A Response object containing the serialized context data.
        """
        # TODO: Fix serializer validation
        serializer = self.__class__.get_response_serializer_class()(
            data=self.context,
            read_only=True,
        )

        return Response(serializer.initial_data, status=http_code)


class UCATokenObtain(UCAView):
    """
    Handles obtaining access and refresh tokens for a user.
    """

    context = UCAContext.get()
    request_serializer_class = UCATokenObtainRequestSerializer
    base_response_serializer_class = UCATokenObtainResponseSerializer

    with_permissions = True

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
        else 60 * 24 * 30
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

        result = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        if self.user_serializer:
            result["user"] = self.user_serializer(instance=user).data

        if self.with_permissions and hasattr(user, "get_all_permissions"):
            result["permissions"] = user.get_all_permissions()

        self.context["result"] = result

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


class UCATokenRefresh(UCAView):
    """
    Handles refreshing an access token using a valid refresh token.
    """

    context = UCAContext.list()
    request_serializer_class = UCATokenRefreshRequestSerializer
    base_response_serializer_class = UCATokenRefreshResponseSerializer

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
        else 60 * 24 * 30
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

        result = {
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

        if self.user_serializer:
            result["user"] = self.user_serializer(instance=user).data

        self.context["result"] = result

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
    request_serializer_class = UCAListViewRequestSerializer
    base_response_serializer_class = UCAListViewResponseSerializer
    action_name = "view"

    distinct_objects = False
    request_order_required = True
    request_pagination_required = True

    @classmethod
    def get_response_serializer_class(cls, view=None):
        combined_serializer = type(
            f"{cls.__name__}ResponseSerializer",
            (cls.base_response_serializer_class,),
            {},
        )

        return combined_serializer

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
            self.__class__.get_model_return_serializer_class(self)(
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
    request_serializer_class = UCAGetViewRequestSerializer
    base_response_serializer_class = UCAGetViewResponseSerializer
    action_name = "view"

    model_class = None

    @classmethod
    def get_response_serializer_class(cls, view=None):
        combined_serializer = type(
            f"{cls.__name__}ResponseSerializer",
            (cls.base_response_serializer_class,),
            {"result": cls.get_model_return_serializer_class()()},
        )

        return combined_serializer

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
        serialized_obj = self.__class__.get_model_return_serializer_class(self)(
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
    request_serializer_class = UCAAddViewRequestSerializer
    base_response_serializer_class = UCAAddViewResponseSerializer
    action_name = "add"

    model_class = None
    model_serializer_class = None

    @classmethod
    def get_response_serializer_class(cls, view=None):
        combined_serializer = type(
            f"{cls.__name__}ResponseSerializer",
            (cls.base_response_serializer_class,),
            {"result": cls.get_model_return_serializer_class()()},
        )

        return combined_serializer

    @classmethod
    def get_model_serializer_class(cls, view=None):
        return cls.model_serializer_class

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
        serializer = self.__class__.get_model_serializer_class(self)(
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
                "result": self.__class__.get_model_return_serializer_class()(
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
    request_serializer_class = UCAChangeViewRequestSerializer
    base_response_serializer_class = UCAChangeViewResponseSerializer
    action_name = "change"

    model_class = None
    model_serializer_class = None

    @classmethod
    def get_model_serializer_class(cls, view=None):
        return cls.model_serializer_class

    @classmethod
    def get_response_serializer_class(cls, view=None):
        combined_serializer = type(
            f"{cls.__name__}ResponseSerializer",
            (cls.base_response_serializer_class,),
            {"result": cls.get_model_return_serializer_class()()},
        )

        return combined_serializer

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

        serializer = self.__class__.get_model_serializer_class(self)(
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
                "result": self.__class__.get_model_return_serializer_class()(
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
    request_serializer_class = UCADeleteViewRequestSerializer
    base_response_serializer_class = UCADeleteViewResponseSerializer
    action_name = "delete"

    model_class = None

    def get_queryset(self):
        """
        Constructs and returns the queryset with optional filtering, annotation, and ordering.
        """
        queryset = self.model_class.objects
        if not isinstance(self.request_filter, Q):
            raise UCAFilterWrongFormat()

        queryset = self.annotate_queryset(queryset).filter(self.request_filter)

        return queryset

    def hook_before_deletion(self, queryset):
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
        queryset = self.get_queryset()

        excludes = set()
        for obj in queryset:
            has_perm = self.check_object_permission(
                obj, self.action_name, should_raise=queryset.count() == 1
            )
            if not has_perm:
                excludes.add(obj)

        queryset = queryset.exclude(id__in=[obj.id for obj in excludes])

        self.hook_before_deletion(queryset)

        queryset.delete()

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
