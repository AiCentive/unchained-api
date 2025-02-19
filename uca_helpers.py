import binascii
import functools
import os
import re
from datetime import timedelta

from django.contrib.auth.models import AnonymousUser
from django.db.models import Q
from django.db.models.functions import Lower, Upper
from rest_framework import permissions
from rest_framework import exceptions

import ast
import operator as op

from api.uca_exceptions import UCAAuthInvalid, UCAValueError


def eval_(node):
    operators = {
        ast.Add: op.add,
        ast.Sub: op.sub,
        ast.Mult: op.mul,
        ast.Div: op.truediv,
        ast.Pow: op.pow,
        ast.BitXor: op.xor,
        ast.USub: op.neg,
        ast.BitAnd: op.and_,
        ast.BitOr: op.or_,
        ast.Invert: op.invert,
    }

    if isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.BinOp):
        return operators[type(node.op)](eval_(node.left), eval_(node.right))
    elif isinstance(node, ast.UnaryOp):
        return operators[type(node.op)](eval_(node.operand))
    elif isinstance(node, ast.Call):
        if node.func.id == "Q":
            if isinstance(node.keywords[0].value, ast.Constant):
                return Q(**{node.keywords[0].arg: node.keywords[0].value.value})
            elif isinstance(node.keywords[0].value, ast.Tuple):
                return Q(**{node.keywords[0].arg: eval_(node.keywords[0].value)})
            elif isinstance(node.keywords[0].value, ast.List):
                return Q(**{node.keywords[0].arg: eval_(node.keywords[0].value)})
            elif isinstance(node.keywords[0].value, ast.BinOp):
                return Q(**{node.keywords[0].arg: eval_(node.keywords[0].value)})
            elif isinstance(node.keywords[0].value, ast.UnaryOp):
                return Q(**{node.keywords[0].arg: eval_(node.keywords[0].value)})
            else:
                raise UCAValueError(
                    "eval_ does not support this function. Hi exploiter :)"
                )
        elif node.func.id == "Lower":
            return Lower(node.args[0].value)
        elif node.func.id == "Upper":
            return Upper(node.args[0].value)
        else:
            raise UCAValueError("eval_ does not support this function. Hi exploiter :)")
    elif isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Tuple):
        return [eval_(elt) for elt in node.elts]
    elif isinstance(node, ast.List):
        return [eval_(elt) for elt in node.elts]
    else:
        raise UCAValueError("eval_ does not support this node. Hi exploiter :)")


class UCAHelpers:
    class AllowMissingDict(dict):
        def __missing__(self, key):
            return "{" + key + "}"

    class NoneToEmptyStringDict(dict):
        def __getitem__(self, key):
            return "" if super().__getitem__(key) is None else super().__getitem__(key)

    @staticmethod
    def parse_string(val, template_vars):
        # Template: [% var1 %]
        res = val

        matches = re.finditer(r"\[(.*?)\]", str(val))

        for match in matches:
            var = re.search("(?<=\[%).+?(?=\%])", match.group(0)).group(0)
            res = res.replace(match.group(0), str(template_vars[var]))

        return res

    @staticmethod
    def eval_expr(expr):
        if not expr:
            return None

        return eval_(ast.parse(expr, mode="eval").body)

    @staticmethod
    def daterange(date1, date2):
        for n in range(int((date2 - date1).days) + 1):
            yield date1 + timedelta(n)

    @staticmethod
    def rgetattr(obj, attr, *args):
        def _getattr(obj, attr):
            return getattr(obj, attr, *args)

        return functools.reduce(_getattr, [obj] + attr.split("."))

    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")

        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]

        else:
            ip = request.META.get("REMOTE_ADDR")

        return ip

    @staticmethod
    def get_client_user_agent(request):
        user_agent = request.META.get("HTTP_USER_AGENT")

        if not user_agent:
            raise UCAValueError("HTTP_USER_AGENT missing.")

        return user_agent

    @staticmethod
    def permission_required(permission_name, raise_exception=False):
        class PermissionRequired(permissions.BasePermission):
            def has_permission(self, request, view):
                if not request.user or isinstance(request.user, AnonymousUser):
                    raise UCAAuthInvalid()

                if not request.user.has_perm(permission_name):
                    if raise_exception:
                        raise exceptions.PermissionDenied(
                            "Permission denied. Required: " + permission_name
                        )

                    return False

                return True

        return PermissionRequired

    @staticmethod
    def encrypt_context(context):
        context.update(
            {
                str(
                    binascii.hexlify(os.urandom(150)).decode()[0:150]
                ): binascii.hexlify(os.urandom(150)).decode()[0:150]
            }
        )
        return {"data": ApiCrypto.encode(context)}

    @staticmethod
    def round_float(value, precision) -> str:
        return ("%." + str(precision) + "f") % (value,)

    @staticmethod
    def list_get(l, i, default):
        try:
            return l[i]
        except IndexError:
            return default

    @staticmethod
    def generate_model_field_permissions(permission, content_type, model):
        for action in ["add", "change", "view"]:
            for field in model._meta.get_fields():
                perm, _ = permission.objects.get_or_create(
                    content_type=content_type.objects.get(
                        app_label=model._meta.app_label,
                        model=model._meta.model_name,
                    ),
                    codename="%s_%s_%s"
                    % (
                        action,
                        model._meta.model_name,
                        field.name,
                    ),
                )
                perm.name = "Can %s %s.%s" % (
                    action,
                    model._meta.model_name,
                    field.name,
                )
                perm.save()

                print(perm.codename)

    @staticmethod
    def add_set(target, item):
        l = len(target)
        target.add(item)
        return l != len(target)

    @staticmethod
    def contains_keys(target, keys):
        return all(key in target for key in keys)

    @staticmethod
    def contains_any_keys(target, keys):
        return any(key in target for key in keys)
