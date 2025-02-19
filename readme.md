# UCA - Unchained API

## Overview

**UCA (Unchained API)** is an API wrapper built on **Django Rest Framework (DRF)**, providing a structured and reusable
approach to handling authentication, pagination, filtering, ordering, and exception handling. This documentation
explores the core views provided by UCA, along with their dependencies and functionalities.

## Installation

### Prerequisites

- Python 3.9+
- Django
- Django REST Framework
- PostgreSQL (recommended for production)

## UCA Views

The **`uca_views.py`** file contains multiple reusable DRF API views, built to provide standardized CRUD operations,
authentication, and structured API responses.

### 1. `UCAView` (Base Class for All Views)

This is the foundational class for all API views, providing:

- **Context Management**: Uses `UCAContext` from `uca_context.py` to structure responses.
- **Request Processing**: Handles request validation, filtering (`request_filter`), ordering (`request_order`), and
  pagination (`request_pagination`).
- **Authentication**: JWT-based authentication via `UCAAuthentication` in `uca_jwt.py`.
- **Transaction Support**: Ensures database consistency with Django’s `transaction.atomic()`.
- **Object Permission Checks**: Uses `check_object_permission()` for access control.

#### Dependencies:

- `UCAContext` from `uca_context.py`: Manages standardized API responses.
- `UCAAuthInvalid` and related exceptions from `uca_exceptions.py`: Handles authentication failures.
- `UCAHelpers` from `uca_helpers.py`: Utility functions for IP retrieval and user agent extraction.
- `decode_jwt` from `uca_jwt.py`: JWT authentication.
- `UCAPaginator` from `uca_paginator.py`: Custom pagination.

---

### 2. `UCATokenAuth` - JWT Authentication

Handles user authentication and token generation.

#### How It Works:

1. **User Authentication**: Uses Django’s built-in `authenticate()` method.
2. **Token Generation**: Uses `create_jwt()` from `uca_jwt.py`.
3. **User Context**: Adds serialized user data (`user_serializer`).

#### Dependencies:

- `decode_jwt` & `create_jwt` from `uca_jwt.py`: Manages JWT authentication.
- `UCAAuthInvalid` from `uca_exceptions.py`: Handles invalid credentials.
- `UCAHelpers.get_client_user_agent()`: Extracts user agent details.

#### Example Request:

```json
{
  "data": {
    "username": "test_user",
    "password": "securepassword"
  },
  "flags": {
    "custom_flag": "value"
  }
}
```

---

### 3. `UCATokenRefresh` - Refresh JWT Tokens

Allows users to refresh their access token using a valid refresh token.

#### Dependencies:

- `decode_jwt` & `create_jwt` from `uca_jwt.py`: Manages JWT authentication.
- `UCAAuthRefreshTokenInvalid` from `uca_exceptions.py`: Handles invalid refresh tokens.

#### Example Request:

```json
{
  "data": {
    "refresh_token": "existing_refresh_token"
  },
  "flags": {
    "custom_flag": "value"
  }
}
```

---

### 4. `UCAListView` - Retrieve a List of Objects

Fetches paginated, filtered, and ordered results.

#### Key Features:

- **Filters** objects dynamically using `Q` conditions.
- **Orders** objects using `request_order`.
- **Paginates** results using `UCAPaginator`.

#### Dependencies:

- `UCAPaginator` from `uca_paginator.py`: Handles API pagination.
- `UCAFilterWrongFormat` from `uca_exceptions.py`: Validates filter format.

#### Example Request:

```json
{
  "filter": "Q(username__icontains='test')",
  "order": [
    "-username"
  ],
  "pagination": {
    "limit": 10,
    "offset": 0
  },
  "flags": {
    "custom_flag": "value"
  }
}
```

---

### 5. `UCAGetView` - Retrieve a Single Object

Fetches an object by ID or filters.

#### Dependencies:

- `UCAFilterWrongFormat` from `uca_exceptions.py`: Validates filter format.

#### Example Request:

```json
{
  "filter": "Q(id='d2a9fcaf-68b9-400c-8d16-c145c4f6f478')",
  "flags": {
    "custom_flag": "value"
  }
}
```

---

### 6. `UCAAddView` - Create a New Object

Validates and saves a new object to the database.

#### Dependencies:

- `UCASerializerInvalid` from `uca_exceptions.py`: Handles validation failures.

#### Example Request:

```json
{
  "data": {
    "name": "New Item",
    "status": "active"
  },
  "flags": {
    "custom_flag": "value"
  }
}
```

---

### 7. `UCAChangeView` - Update an Existing Object

Modifies an existing object using partial updates.

#### Example Request:

```json
{
  "data": {
    "id": "44b7153c-c047-4a58-a036-cd92b1c7bb35",
    "name": "Updated Item",
    "status": "inactive"
  },
  "flags": {
    "custom_flag": "value"
  }
}
```

---

### 8. `UCADeleteView` - Remove an Object

Deletes an object by ID.

#### Example Request:

```json
{
  "filter": "Q(id='d2a9fcaf-68b9-400c-8d16-c145c4f6f478')",
  "flags": {
    "custom_flag": "value"
  }
}
```

---

## Summary of Provided Views

| View              | Purpose                                   |
|-------------------|-------------------------------------------|
| `UCAView`         | Base class for API views.                 |
| `UCATokenAuth`    | Handles user login and JWT generation.    |
| `UCATokenRefresh` | Refreshes JWT tokens.                     |
| `UCAListView`     | Retrieves a paginated list of objects.    |
| `UCAGetView`      | Fetches a single object based on filters. |
| `UCAAddView`      | Creates a new database record.            |
| `UCAChangeView`   | Updates an existing object.               |
| `UCADeleteView`   | Deletes an object from the database.      |

## License

MIT License - See `LICENSE` for details.

