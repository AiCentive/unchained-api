class UCAContext:
    default_context = {"success": False, "status": 400, "messages": []}

    @classmethod
    def default(cls):
        ctx = cls.default_context.copy()
        return ctx

    @classmethod
    def list(cls):
        ctx = cls.default_context.copy()
        ctx.update({"results": []})

        return ctx

    @classmethod
    def get(cls):
        ctx = cls.default_context.copy()
        ctx.update({"result": {}, "flags": {}})

        return ctx

    @classmethod
    def create(cls):
        ctx = cls.default_context.copy()
        ctx.update({"result": {}, "flags": {}})

        return ctx

    @classmethod
    def update(cls):
        ctx = cls.default_context.copy()
        ctx.update({"result": {}, "flags": {}})

        return ctx

    @classmethod
    def remove(cls):
        ctx = cls.default_context.copy()

        return ctx

    @classmethod
    def auth(cls):
        ctx = cls.default_context.copy()
        ctx.update({"results": None})

        return ctx
