# unchained-api (UCA) — Claude Code Instructions

## What This Repo Does

UCA is a **utility library** for building REST APIs with Django REST Framework. It provides reusable base classes for authentication, permissions, CRUD views, pagination, and error handling. Think of it as a template — you define your data model, and UCA handles the API boilerplate.

## Is It Used?

**No.** The chatbot's REST API will be built with FastAPI instead (decision: UCA is overkill for a single `/ask` endpoint). UCA is not needed for the thesis.

## What the Student Needs to Know

- UCA exists as a utility library owned by AiCentive GmbH
- It is **not needed** for the thesis — we're using FastAPI for the REST backend instead
- The license is proprietary — cannot redistribute
- Does **not need modification** for the thesis

## File Map

| File | Purpose |
|------|---------|
| `uca_views.py` | Base CRUD views (List, Get, Add, Change, Delete) + JWT auth views |
| `uca_models.py` | Base model with UUID primary key and timestamps |
| `uca_serializers.py` | Base serializer with standard field handling |
| `uca_jwt.py` | JWT token encode/decode using Django's SECRET_KEY |
| `uca_manager.py` | Custom model manager with soft-delete support |
| `uca_helpers.py` | Utility functions (response formatting, permission checks) |
| `uca_exceptions.py` | Standardized error responses |
| `uca_paginator.py` | Cursor-based pagination |
| `uca_cors.py` | CORS middleware |
| `uca_context.py` | Request context processor |
| `uca_spectacular.py` | OpenAPI/Swagger documentation helpers |

## Rules

1. Do not modify code without explicit confirmation
2. This is a proprietary library — treat as read-only for assessment purposes
