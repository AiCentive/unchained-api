from django.db.models import QuerySet

from api.uca_exceptions import UCAValueError
from api.uca_helpers import UCAHelpers


class UCAPaginator:
    offset: int = 0
    limit: int = 0
    page: int = 0
    total: int = 0

    def __init__(self, request_pagination: dict):
        self.get_pagination_data(request_pagination)

    def get_pagination_data(self, request_pagination: dict = {}):
        offset = request_pagination.get("offset")
        limit = request_pagination.get("limit")
        page = request_pagination.get("page")

        self.limit = int(limit) if limit else 25

        if self.limit is None:
            raise UCAValueError("ApiPaginator: limit not provided.")

        if page:
            self.offset = int(page) * self.limit

        else:
            self.offset = int(offset) if offset else 0

    def setup(self, objects):
        result_set = list()
        if isinstance(objects, QuerySet):
            self.total = objects.count()
        elif isinstance(objects, list):
            self.total = len(objects)
        else:
            raise UCAValueError()

        return result_set

    def paginate(
        self,
        objects: list | QuerySet,
        request,
        check_object_permission: bool = True,
    ):
        result_set = self.setup(objects)

        if self.total == 0:
            return result_set

        if self.offset >= self.total:
            raise UCAValueError("ApiPaginator: offset out of range.")

        if self.limit == -1:
            self.limit = self.total

        count = self.limit
        for i, obj in enumerate(objects[self.offset :]):
            if i >= count:
                break

            if check_object_permission:
                if not obj.check_view_perm(request):
                    count += 1
                    self.total -= 1
                    continue

            if isinstance(result_set, list):
                result_set.append(obj)

            elif isinstance(result_set, QuerySet):
                result_set = result_set | obj

        return result_set

    def update_context(self, context):
        context.update(
            {
                "pagination": {
                    "total": self.total,
                    "limit": self.limit,
                    "page": int(self.offset / self.limit),
                    "pages": int(self.total / self.limit),
                    "offset": self.offset,
                }
            }
        )
