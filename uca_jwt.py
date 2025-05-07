import jwt  # PyJWT
import datetime
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.utils.crypto import get_random_string
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication

from api.uca_exceptions import UCAAuthInvalid


def create_jwt(payload, expire_minutes):
    """
    Create a JWT token from a payload.
    """
    expire_delta = timezone.timedelta(minutes=expire_minutes)

    payload["exp"] = datetime.datetime.utcnow() + expire_delta
    payload["bfp"] = get_random_string(128)
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
    return token


def decode_jwt(token):
    """
    Decode a JWT token and return the payload.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError("Token has expired")
    except jwt.InvalidTokenError:
        raise jwt.InvalidTokenError("Invalid token")


class UCAAuthentication(BaseAuthentication):
    """
    Abstract class for handling JWT-based authentication.
    """

    request_header = "HTTP_AUTHORIZATION"
    request_header_key = "Bearer"
    user_model = get_user_model()

    def authenticate(self, request):
        """
        Authenticate the user based on the JWT token in the request header.
        """
        auth_header = request.META.get(self.request_header, "")
        if not self._is_valid_auth_header(auth_header):
            return None, None

        token = auth_header.split(" ")[1]

        try:
            payload = self.get_payload_from_token(token)
            user = self.get_user_from_payload(request, payload)
            return user, token

        except jwt.ExpiredSignatureError:
            raise UCAAuthInvalid("Token has expired")
        except jwt.InvalidTokenError:
            raise UCAAuthInvalid("Invalid token")
        except ObjectDoesNotExist:
            raise UCAAuthInvalid("User not found")
        except Exception as e:
            raise UCAAuthInvalid(e)

    def _is_valid_auth_header(self, auth_header: str) -> bool:
        """
        Validate the structure of the authorization header.
        """
        return auth_header.startswith(f"{self.request_header_key} ")

    def get_user_from_payload(self, request, payload: dict):
        """
        Retrieve the user from the payload using the user ID.
        """
        user_id = payload.get("user_id")
        if not user_id:
            return None

        return self.user_model.objects.get(id=user_id)

    def get_payload_from_token(self, token: str) -> dict:
        """
        Decode the JWT token to extract the payload.
        Override this method to customize token decoding if needed.
        """

        return decode_jwt(token)
