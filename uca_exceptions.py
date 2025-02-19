import logging
import traceback

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
    exception_string = f"{'#'*100}\n{context}\nUser: {user}\n{formatted_exc}\n{'#'*100}"
    logging.getLogger("django").error(f"{exception_string}")

    if not isinstance(exc, APIException):
        exc = APIException(exc)

    context = UCAContext.default()
    context.update(
        {
            "status": exc.status_code,
            "error": {
                "type": exc.status_code,
                "message": exc.default_detail,
                "code": exc.default_code,
            },
        }
    )

    return Response(data=context, status=exc.status_code)


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


class UCASerializerInvalid(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Serializer is invalid."
    default_code = "serializer_invalid"


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


class UCARequestMethodNotAllowed(APIException):
    status_code = status.HTTP_405_METHOD_NOT_ALLOWED
    default_detail = "Method not allowed."
    default_code = "method_not_allowed"
