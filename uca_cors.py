from django.utils.deprecation import MiddlewareMixin
from django.conf import settings


class CORSMiddleware(MiddlewareMixin):
    """
    Middleware to handle CORS (Cross-Origin Resource Sharing).
    """

    def process_response(self, request, response):
        allowed_origins = []
        if hasattr(settings, "UCA_CORS_ALLOWED_ORIGINS"):
            allowed_origins = settings.UCA_CORS_ALLOWED_ORIGINS

        # Allow any origin (not recommended for production)
        if (
            hasattr(settings, "UCA_CORS_ALLOW_ANY_ORIGIN")
            and settings.UCA_CORS_ALLOW_ANY_ORIGIN
        ):
            allowed_origins = ["*"]

        request_origin = request.META.get("HTTP_ORIGIN")

        if request_origin in allowed_origins or "*" in allowed_origins:
            response["Access-Control-Allow-Origin"] = (
                request_origin if request_origin else "*"
            )
            response["Access-Control-Allow-Methods"] = (
                "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            )
            response["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            response["Access-Control-Allow-Credentials"] = "true"

            # Handle preflight requests
            if request.method == "OPTIONS":
                response.status_code = 200

        return response
