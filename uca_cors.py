from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.http import JsonResponse
from rest_framework import status


class CORSMiddleware(MiddlewareMixin):
    """
    Middleware to handle CORS (Cross-Origin Resource Sharing).
    """

    def process_request(self, request):
        """Handle OPTIONS requests before authentication checks."""
        if request.method == "OPTIONS":
            response = JsonResponse(
                {"message": "CORS Preflight OK"}, status=status.HTTP_200_OK
            )
            self.add_cors_headers(request, response)
            return response  # Stop further processing for OPTIONS requests

    def process_response(self, request, response):
        """Attach CORS headers to the response."""
        self.add_cors_headers(request, response)
        return response

    def add_cors_headers(self, request, response):
        """Utility method to add CORS headers."""
        allowed_origins = getattr(settings, "UCA_CORS_ALLOWED_ORIGINS", [])
        if getattr(settings, "UCA_CORS_ALLOW_ANY_ORIGIN", False):
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
