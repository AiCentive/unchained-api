# unchained-api (UCA) — Claude Code Instructions

## What This Repo Does

UCA is a **utility library** for building REST APIs with Django REST Framework. It provides reusable base classes for authentication, permissions, CRUD views, pagination, and error handling. Think of it as a template — you define your data model, and UCA handles the API boilerplate.

## Is It Used?

**Not currently.** The chatbot is a CLI tool. UCA would be needed if/when an HTTP API layer is built for the chatbot (e.g., so the Angular widget can talk to it via REST).

## What the Student Needs to Know

- UCA exists as a utility library owned by AiCentive GmbH
- It is **not needed** for the thesis pipeline or chatbot as they stand today
- If a web API for the chatbot is needed later, UCA would be the framework to use
- The license is proprietary — cannot redistribute
- Probably does **not need modification** for the thesis

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
