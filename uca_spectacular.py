from api.uca_views import (
    UCAListView,
    UCAGetView,
    UCAAddView,
    UCAChangeView,
    UCADeleteView,
)


def uca_extend_schema(cls):
    cls_name = cls.__name__

    if issubclass(cls, UCAListView):
        request_combined = type(
            f"{cls_name}RequestSerializer",
            (cls.request_serializer_class,),
            {},
        )

        response_combined = type(
            f"{cls_name}ResponseSerializer",
            (cls.base_response_serializer_class,),
            {"results": cls.get_model_return_serializer_class()(many=True)},
        )

        return {
            "request": request_combined,
            "responses": {200: response_combined},
        }

    elif issubclass(cls, UCAGetView):
        request_combined = type(
            f"{cls_name}RequestSerializer",
            (cls.request_serializer_class,),
            {},
        )

        response_combined = type(
            f"{cls_name}ResponseSerializer",
            (cls.base_response_serializer_class,),
            {"result": cls.get_model_return_serializer_class()()},
        )

        return {
            "request": request_combined,
            "responses": {200: response_combined},
        }

    elif issubclass(cls, UCAAddView):
        request_combined = type(
            f"{cls_name}RequestSerializer",
            (cls.request_serializer_class,),
            {"data": cls.get_model_serializer_class()()},
        )

        response_combined = type(
            f"{cls_name}ResponseSerializer",
            (cls.base_response_serializer_class,),
            {
                "result": (
                    cls.get_model_return_serializer_class()()
                    if cls.get_model_return_serializer_class()
                    else None
                )
            },
        )

        return {
            "request": request_combined,
            "responses": {201: response_combined},
        }

    elif issubclass(cls, UCAChangeView):
        request_combined = type(
            f"{cls_name}RequestSerializer",
            (cls.request_serializer_class,),
            {"data": cls.get_model_serializer_class()(partial=True)},
        )

        response_combined = type(
            f"{cls_name}ResponseSerializer",
            (cls.base_response_serializer_class,),
            {"result": cls.get_model_return_serializer_class()()},
        )

        return {
            "request": request_combined,
            "responses": {200: response_combined},
        }

    elif issubclass(cls, UCADeleteView):
        return {
            "request": cls.request_serializer_class,
            "responses": {204: cls.base_response_serializer_class},
        }

    else:
        return {
            "request": cls.request_serializer_class,
            "responses": {200: cls.base_response_serializer_class},
        }
