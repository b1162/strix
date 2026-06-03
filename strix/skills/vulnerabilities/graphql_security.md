---
name: graphql-security
description: GraphQL vulnerability testing covering introspection, resolver authorization bypass, batching attacks, query complexity DoS, and GraphQL injection vulnerabilities
---

# GraphQL Security

GraphQL presents unique attack vectors due to its nature as a flexible query language. Because authorization and query parsing are handled differently than in standard REST APIs, resolvers often suffer from inconsistent access control, resources are vulnerable to complexity-based DoS, and query-stretching can bypass security controls.

## Attack Surface

**GraphQL Operations**
- **Queries**: Fetching data; often vulnerable to authorization bypass, information disclosure, and nesting DoS.
- **Mutations**: Writing/modifying data; high impact on IDOR, mass assignment, and input injection.
- **Subscriptions**: Real-time event streams; authorization is often checked only during the initial handshake, allowing subsequent unauthorized access.

**Endpoints & Transport**
- Typical paths: `/graphql`, `/api/graphql`, `/v1/graphql`, `/gql`, `/api/v1/graphql`.
- Transports: HTTP POST (JSON/multipart), HTTP GET (query parameters), WebSocket (graphql-ws, graphql-transport-ws).

**Schema Definition & Introspection**
- Introspection queries (`__schema`, `__type`, `__typename`) that expose the entire database model, query names, arguments, and types.
- Field suggestion errors that reveal field names even when introspection is disabled.

---

## Detection & Discovery

### 1. Introspection Probes
Verify if introspection is enabled by sending:
```graphql
query {
  __schema {
    types {
      name
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

### 2. Schema Harvesting (Disabled Introspection)
If introspection is disabled:
- Trigger **Field Suggestions**: submit a close approximation of a field name (e.g., `emil` instead of `email`) to harvest recommendations like *"Did you mean 'email'?"*.
- Analyze **Type Coercion**: supply an array where a string is expected to trigger errors detailing expected types.

---

## Key Vulnerabilities

### 1. Introspection & Schema Disclosure
- **Vulnerability**: Introspection endpoints left active in production.
- **Impact**: Attacker gathers structural information, discovering administrative queries/mutations.
- **Testing**: Send `{__typename}` to confirm it is a GraphQL endpoint, then send the full `__schema` query.

### 2. Broken Object Level Authorization (IDOR) & Resolver Bypass
- **Field-Level IDOR**: Test with aliases to retrieve multiple records (owned vs foreign) in a single request:
  ```graphql
  query {
    ownedRecord: order(id: "OWNED_ID") { id total }
    foreignRecord: order(id: "FOREIGN_ID") { id total }
  }
  ```
- **Resolver Cascades**: Parent resolver checks authorization, but child/nested resolvers assume the parent check was sufficient:
  ```graphql
  query {
    user(id: "FOREIGN_USER_ID") {
      id
      privateData {
        secretKey  # Exposes secrets if nested resolver skips authorization
      }
    }
  }
  ```
- **Relay Global Node Resolution**: Decode base64 global IDs, swap underlying database IDs, and query `node` directly:
  ```graphql
  query {
    node(id: "VXNlcjoxMjM=") { ... on User { email } }
  }
  ```

### 3. Batching & Alias Abuse
- **Alias-Based Bruteforcing**: Submit hundreds of calls in one request to bypass standard IP-based rate limiting:
  ```graphql
  mutation {
    attempt1: login(username: "admin", password: "123") { token }
    attempt2: login(username: "admin", password: "abc") { token }
  }
  ```
- **Array Batching**: Send multiple operations in an array `[ {query:...}, {query:...} ]` to bypass request-level constraints.

### 4. Query Complexity & Denial of Service (DoS)
- **Deep Nesting / Circular Relationships**: Craft deeply nested relationships to exhaust server memory/CPU:
  ```graphql
  query {
    user {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
  ```
- **Fragment Bombs**: Inject circular fragment spreads to produce infinite recursion:
  ```graphql
  fragment bomb on User { friends { ...bomb } }
  query { me { ...bomb } }
  ```

### 5. GraphQL Injection (Resolvers)
- **SQL/NoSQL Injection**: Arguments in resolvers passed directly to database queries without parameterized inputs.
- **Command Injection**: Scalar fields or inputs used by resolvers to execute shell commands.
- **SSRF**: Resolvers fetching custom URLs/images from argument values.

### 6. CSRF & Transport Vulnerabilities
- **GET Request Mutations**: Mutations mapped to HTTP GET requests. If session authentication relies on cookies, this allows standard CSRF attacks via static images or scripts.

### 7. File Upload Attacks
- **Upload Scalar Exploitation**: Test custom mutations handling `Upload` types for path traversal or arbitrary file execution if validation is performed only on client-side content types.

---

## Bypass & Evasion Techniques

**Query Reshaping**
- Inject **GraphQL Comments** (`#`) and **Block Strings** (`"""`) to change the textual signature of queries, bypassing naive regex-based Web Application Firewalls (WAFs).
- Use **Unicode escapes** inside strings to evade keyword filters.

**Fragment Splitting**
Split fields across multiple fragments to bypass signature checks matching single queries containing sensitive fields:
```graphql
fragment partA on User { email }
fragment partB on User { password }
query { me { ...partA ...partB } }
```

**Transport Switching**
Convert a POST request payload into a GET query string, or swap `application/json` for `application/graphql` or `multipart/form-data`.

---

## Testing Methodology

1. **Fingerprint**: Identify all GraphQL endpoints using dictionary brute-forcing. Find exposed dev panels (GraphiQL, GraphQL Playground).
2. **Schema Extraction**: Dump schema via introspection. If disabled, reconstruct using suggestions.
3. **Map Queries & Mutations**: Extract all endpoints and parameters, identifying sensitive objects (users, billing, configs) and actions (create, delete, edit).
4. **Test Access Controls**: Compare query outputs across multiple privilege levels (unauthenticated, user, admin) using aliases to request foreign resources.
5. **Verify Limits**: Probe nesting depth limit limits, batching capacity limits, and memory usage.
6. **Inject Arguments**: Inject special characters (`'`, `"`, `$gt`, `|`) into field arguments to check for SQL/NoSQL/Command injection.

---

## Validation

1. Provide reproducible queries and variables that demonstrate a successful bypass (e.g. accessing a foreign record).
2. Show before-and-after responses demonstrating control of variables/arguments.
3. Quantify complexity limits by showing at what nesting level or query cost the request is blocked.

---

## False Positives

- Generic "Internal Server Error" messages that do not indicate successful exploit execution.
- Suggestion messages containing common fields that do not actually exist on the target schema.
- Local time differences interpreted as timing-based injection.

---

## Impact

- Full database compromise via SQL/NoSQL injection in resolvers.
- Complete data leakage through unauthorized schema queries.
- Bypassing multi-factor authentication or brute-force protections via alias batching.
- Denial of Service (DoS) crashing the API gateway or backend database.

---

## Pro Tips

1. Always check the `_entities` query in Apollo Federated gateways; subgraphs often skip authentication checks.
2. If `__schema` is blocked, query `__type(name: "Query")` to get a list of all query entry points directly.
3. Test if mutations are accepted over HTTP GET requests with query strings to enable cookie-based CSRF.
4. Try passing arguments as JSON variables vs. inline values; WAF rules often check only inline string parameters.
5. Audit custom authentication directives (e.g. `@auth`) to ensure they execute resolver checks rather than just annotating schema definitions.
