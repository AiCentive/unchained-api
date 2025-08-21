import logging
import traceback
from collections import defaultdict

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import ProtectedError
from rest_framework.exceptions import APIException
from rest_framework import status
from rest_framework.response import Response
from .uca_context import UCAContext


def uca_exception_handler(exc, context):
    request = context.get("request")

    user = None
    if hasattr(request, "user"):
        user = request.user

    formatted_exc = "\n".join(traceback.format_exception(exc))
    exception_string = f"\n{'#'*100}\n{context}\nUser: {user.__dict__ if hasattr(user, '__dict__') else user}\n{formatted_exc}\n{'#'*100}"
    logging.getLogger("django").error(f"{exception_string}")

    if isinstance(exc, ObjectDoesNotExist):
        exc = UCAObjectDoesNotExist(exc)
    elif isinstance(exc, ProtectedError):
        exc = UCAProtectedError(exc)
    elif not isinstance(exc, APIException):
        exc = APIException(exc)

    context = UCAContext.default()

    # Create basic error structure
    error_data = {
        "type": exc.status_code,
        "message": getattr(exc, "detail", getattr(exc, "default_detail", "error")),
        "code": getattr(exc, "code", getattr(exc, "default_code", "error")),
    }

    # Add field_errors for UCASerializerInvalid exceptions
    if isinstance(exc, UCASerializerInvalid) and getattr(exc, "field_errors", None):
        field_errors = defaultdict(list)
        for field, errors in exc.field_errors.items():
            field_errors[field].extend(
                error.code if hasattr(error, "code") else str(error) for error in errors
            )
        error_data["field_errors"] = dict(field_errors)

    context.update(
        {
            "status": exc.status_code,
            "error": error_data,
        }
    )

    return Response(data=context, status=exc.status_code)


class UCAException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Data not found or malformatted"
    default_code = "data_wrong_format"


class UCAAuthInvalid(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Authentication credentials were not valid."
    default_code = "auth_invalid"


class UCAAuthRefreshTokenInvalid(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = "Refresh token is invalid."
    default_code = "auth_refresh_token_invalid"


class UCAFilterWrongFormat(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Filter is not in correct format."
    default_code = "filter_wrong_format"


class UCAPaginationNotProvided(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Pagination is not provided."
    default_code = "pagination_not_provided"


class UCAOrderNotProvided(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Order is not provided."
    default_code = "order_not_provided"


class UCAObjectPermissionDenied(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "You do not have permission to perform this action."
    default_code = "permission_denied"


class UCAObjectPermissionCheckError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = "Error checking object permission."
    default_code = "permission_check_error"


class UCAPermissionError(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = "Permission error."
    default_code = "permission_error"


class UCASerializerInvalid(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Serializer validation failed"
    default_code = "serializer_invalid"

    def __init__(self, field_errors=None, detail=None, code=None):
        """
        Initialize UCASerializerInvalid exception with field-level validation errors.

        Args:
            field_errors: Django REST framework serializer errors dictionary
            detail: Optional custom detail message
            code: Optional custom error code
        """
        self.field_errors = field_errors or {}

        if detail is not None:
            self.detail = detail
        else:
            self.detail = self.default_detail

        if code is not None:
            self.default_code = code


class UCADataIdNotProvided(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "data.id is not provided."
    default_code = "data_id_not_provided"


class UCAEmptyRequestError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Empty request."
    default_code = "empty_request"


class UCAValueError(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Value error."
    default_code = "value_error"


class UCAValueConflict(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Value conflict."
    default_code = "value_conflict"


class UCARequestMethodNotAllowed(APIException):
    status_code = status.HTTP_405_METHOD_NOT_ALLOWED
    default_detail = "Method not allowed."
    default_code = "method_not_allowed"


class UCAObjectDoesNotExist(APIException):
    status_code = status.HTTP_404_NOT_FOUND
    default_detail = "Object does not exist."
    default_code = "object_does_not_exist"


class UCAProtectedError(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_code = "error_protected"
    default_detail = "Delete blocked by protected foreign key."

    def __init__(self, exc: ProtectedError):
        # exc.args[0] is the human string, exc.args[1] is a set of protected objects
        related_objects = list(exc.protected_objects)
        # Try to infer relation: "<Model>.<field>"
        # Django includes that in the str(exc)
        relation_detail = None
        if isinstance(exc.args[0], str):
            # crude parse, but enough: e.g.
            # "Cannot delete some instances of model 'School' because they are referenced through protected foreign keys: 'Student.school'."
            msg = exc.args[0]
            if ":" in msg:
                relation_detail = msg.split(":")[-1].strip().strip(".").strip("'")

        self.detail = relation_detail or "unknown"
