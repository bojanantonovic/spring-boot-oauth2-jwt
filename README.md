# spring-boot-oauth2-jwt

Stateless JWT authentication for a Spring Boot 4 / Spring Security 7 REST API, built on
`spring-boot-starter-security-oauth2-resource-server` instead of a hand-written JWT filter.

It is the OAuth2 variant of [`spring-boot-jwt`](../spring-boot-jwt): same endpoints, same domain model, same
tests — only the token handling differs.

## Endpoints

| Method | Path                 | Access        | Description                                     |
|--------|----------------------|---------------|-------------------------------------------------|
| `POST` | `/api/auth/register` | public        | Creates a user and returns an access token      |
| `POST` | `/api/auth/login`    | public        | Verifies the password and returns a token       |
| `GET`  | `/api/users/me`      | bearer token  | Returns the subject and authorities of the token |

## How the token handling works

**Issuing** — `TokenService` builds a `JwtClaimsSet` (`iss`, `iat`, `exp`, `sub` and a custom `roles` claim) and
signs it with the `JwtEncoder` from `JwtConfiguration` (`NimbusJwtEncoder`, HS256, shared secret).

**Verifying** — no application code is involved. `SecurityConfiguration` enables `oauth2ResourceServer(...jwt(...))`,
which installs Spring Security's `BearerTokenAuthenticationFilter`. It reads the `Authorization` header, hands the
token to the `JwtDecoder` bean (`NimbusJwtDecoder` plus `JwtValidators.createDefaultWithIssuer`) and answers with
`401` and a `WWW-Authenticate: Bearer error="invalid_token"` header if anything is wrong — signature, `exp`, `nbf`
or `iss`.

**Authorities** — the `roles` claim is mapped back to `ROLE_`-prefixed authorities by a
`JwtGrantedAuthoritiesConverter`. Without that converter only `SCOPE_`-prefixed authorities from a `scope` claim
would exist. Spring Security 7 additionally adds a `FACTOR_BEARER` authority to every bearer-authenticated request.

`JwtConventions` holds the three settings the encoder and the decoder have to agree on: signature algorithm, claim
name for the roles, and the authority prefix.

## What this buys over a hand-written filter

* **No filter to get wrong.** A token that cannot be parsed cannot make an exception escape the filter chain, which
  is the classic way of turning a `401` into a `500`.
* **RFC 6750 error responses**, including the `WWW-Authenticate` challenge, out of the box.
* **Standard claim validation** (`exp`, `nbf`, `iss`, clock skew) instead of a hand-rolled expiry check.
* **jjwt is not needed**; the starter brings Nimbus for both signing and verifying.
* **Migration path**: pointing the app at a real identity provider (Keycloak, Entra ID, Auth0) mainly means
  replacing the `JwtDecoder` bean with one built from an `issuer-uri`. Controllers and rules stay as they are.

## The trade-off: no database lookup per request

The token is self-contained, so an authenticated request never touches the database — that is the point of a
resource server, and it is also the price: a token stays valid until it expires, even if the user has been deleted
or locked in the meantime. `AuthControllerTest.givenTokenOfDeletedUser_...` documents exactly that behaviour.

Short token lifetimes plus refresh tokens are the usual answer. If immediate revocation is required, register an
additional `OAuth2TokenValidator<Jwt>` on the `JwtDecoder` (checking a deny list or a `UserDetailsService`) — which
brings the per-request lookup, and its cost, back.

## Configuration

```yaml
app:
  jwt:
    secret: "…"                     # at least 256 bits for HS256; use an environment variable in production
    issuer: http://localhost:8080   # written as `iss` and enforced by the decoder; must be a URI
    expiration-ms: 3600000
  cors:
    allowed-origins: http://localhost:4200
```

Because the application defines its own `JwtDecoder` bean, no `spring.security.oauth2.resourceserver.*` property is
needed — Boot's auto-configuration backs off.

## Running

```bash
./mvnw spring-boot:run
./mvnw test
```

An in-memory H2 database is used; its console is available at `/h2-console`.
