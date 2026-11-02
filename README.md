# Spring Boot JWT Authentication Template

A robust, production-ready, stateless JWT (JSON Web Token) authentication and authorization module built with **Spring Boot** and **Spring Security**.

This template implements a secure **Access Token & Refresh Token** rotation flow, role-based access control (RBAC), custom claims handling, and clean request filtering.

---

## Architecture & How It Works

The authentication mechanism revolves around a stateless security model using JSON Web Tokens. Here is the step-by-step lifecycle of how requests and security are handled:

1. **Registration & Password Hashing (`AuthService`)**
* New users register via `/api/v1/auth/register`.


* Passwords are securely hashed using **BCrypt** (`BCryptPasswordEncoder`) before being stored in the database.




2. **Authentication & Token Generation (`AuthService` & `JwtService`)**
* During login (`/api/v1/auth/login`), Spring's `AuthenticationManager` verifies the user's email and password against the database via `UserDetailsServiceImpl`.


* Upon successful authentication, `JwtService` issues a **TokenPair** containing:


* **Access Token**: Short-lived token containing user claims (`id`, `email`, `name`, `role`) used to authorize protected endpoint requests.


* **Refresh Token**: Longer-lived token used exclusively to request a fresh Access Token when the old one expires.






3. **Request Interception & Filtering (`JwtAuthenticationFilter`)**
* For every incoming HTTP request, `JwtAuthenticationFilter` intercepts the call and checks for the `Authorization: Bearer <TOKEN>` header.


* It parses and validates the token signature and expiration via `JwtService`.


* If valid, it extracts the user's UUID and role, wraps them in a `UsernamePasswordAuthenticationToken`, and populates the **Spring Security Context** (`SecurityContextHolder`), authenticating the user for that request thread.




4. **Endpoint Protection & Authorization (`SecurityConfig`)**
* `SecurityConfig` defines granular URL-based rules (e.g., public endpoints, organizer actions, and admin routes).


* `@EnableMethodSecurity` is enabled to support method-level security (e.g., `@PreAuthorize`) inside controllers if needed.




5. **Current User Context Injection (`UserService`)**
* Inside your business logic or controllers, you can fetch the currently logged-in user instantly without extra database queries for credentials by calling:


```java
User currentUser = userService.getCurrentUser();

```



