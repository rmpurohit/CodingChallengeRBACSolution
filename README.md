# Challenge: Implement Role-Based Access Control (RBAC) for the "Products" API

## Objective (User Story)

As an **admin**, I want to manage products by adding, updating, and deleting them using a secure REST API, so that I can control the product inventory.  
As a **user**, I want to view products but not have the ability to modify them, so that I can safely browse the product list without making accidental changes.

## Description

In this challenge, you are required to extend an existing Java Spring Boot project by implementing **Role-Based Access Control (RBAC)**. The existing project contains:
- A REST API for managing **products** with CRUD operations.
- A database pre-populated with **5 products**.
- Unprotected CRUD endpoints (`GET`, `POST`, `PUT`, `DELETE`) for products.

You must secure the API endpoints by implementing **Spring Security** and assigning role-based access to them. There should be two roles:
- **Admin**: Can access all CRUD operations (create, update, delete, and view products).
- **User**: Can only view products (read-only access).

This challenge needs to be completed in **Java** with **Spring Boot**. You must ensure that the project compiles and includes unit/integration tests that verify the expected behavior of the RBAC functionality.

## Acceptance Criteria

1. **Basic Authentication Setup**:
    - Implement basic authentication in the project using **Spring Security**.
    - Define two roles: **Admin** and **User**.
    - Store credentials and roles in-memory (or another method, if preferred).

2. **Role-Based Access Control**:
    - Protect the CRUD endpoints for products.
    - Ensure that **Admin** users can perform all operations (`GET`, `POST`, `PUT`, `DELETE`).
    - Ensure that **User** users can only perform `GET /products` and `GET /products/{id}` (read-only access).
    - Block access to `POST`, `PUT`, and `DELETE` for **User** users and return a `403 Forbidden` response.

3. **Error Handling**:
    - Unauthorized access attempts should return an appropriate **403 Forbidden** status with a meaningful error message.

4. **Testing**:
    - Write unit and/or integration tests to verify:
        - Admin users have full access to all CRUD operations.
        - User users can only view products.
        - Unauthorized users are prevented from accessing restricted endpoints.
    - Ensure the tests cover various scenarios, such as incorrect credentials or unauthorized access.

5. **Code Quality**:
    - Ensure the code is clean, well-organized, and follows industry best practices.
    - Provide comments where necessary to explain key parts of the code.

## Provided Resources

- A **Spring Boot** project with the following:
    - Existing CRUD endpoints for managing products.
    - A **database** containing 5 products.
    - Endpoints are currently **unprotected**.

You are required to extend this project to fulfill the above requirements. At the end of the challenge, the project must compile and include tests that ensure the expected RBAC functionality is correctly implemented.

## Solution

The Products API is secured with Spring Security using HTTP Basic authentication and role based access control. All existing endpoints and business logic remain unchanged. The security layer was added on top through a dedicated configuration.

### Design Notes

Centralized authorization rules. All access rules live in one place (SecurityConfig) as URL based rules, so the existing controllers stay untouched and any future endpoint is protected by default through the fail closed anyRequest rule.
Swappable user storage. Users sit behind the UserDetailsService interface, so the in memory store can later be replaced by a database or an identity provider without changing the authorization configuration.
Stateless API. Sessions are disabled and CSRF protection is turned off, since there are no cookie based sessions for cross site request forgery to exploit.
Consistent error responses. Security errors (401 and 403) are handled by dedicated handlers sharing one APIErrorResponse shape, because these events occur in the filter chain before controller level error handling is available.

### Users

- user / userPass (role USER)
- admin / adminPass (role ADMIN)

### Access rules

- GET endpoints require the USER or ADMIN role
- POST, PUT and DELETE require the ADMIN role
- Requests without valid credentials receive 401 Unauthorized.
- Authenticated requests without the required role receive 403 Forbidden.

### Running the tests

./gradlew test

Integration tests in ProductAPISecurityTest cover anonymous access,
invalid credentials, USER restrictions, and admin CRUD.
