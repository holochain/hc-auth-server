# Rust OAuth Service

A Rust-based web service implementing OAuth2 authentication with GitHub, verifying organization and team membership.

## For Developers

### Architecture Overview

This project is built using:
- **Axum**: A modular and ergonomic web framework for Rust.
- **Tokio**: An asynchronous runtime for reliable network applications.
- **Askama**: Type-safe HTML templates.
- **Tower Cookies**: Cookie management for session handling.
- **OAuth2**: Basic OAuth2 client implementation for GitHub authentication.

#### Code Structure
- `src/main.rs`: Application entry point. Sets up logging, loads configuration, defines routes, and starts the server.
- `src/config.rs`: Manages application configuration loaded from environment variables.
- `src/routes_client.rs`: Handlers for client-facing authentication routes.
- `src/routes_ops.rs`: Handlers for web-based administrative operations (OAuth, dashboard).
- `src/routes_api.rs`: Handlers for programmatic administrative API access.
- `src/storage.rs`: Abstracted storage layer for Redis interaction.
- `src/github.rs`: Utilities for interacting with the GitHub API.
- `templates/`: HTML templates used by the application.

### Getting Started

#### Prerequisites
- Rust (2024 edition)
- A GitHub OAuth Application (setup instructions below)

#### Setting up GitHub OAuth App

To run this application, you need to register a new OAuth application on GitHub:

1.  Go to your GitHub [Developer Settings](https://github.com/settings/developers).
2.  Select **OAuth Apps** and click **New OAuth App**.
3.  Fill in the details:
    - **Application Name**: `Rust OAuth Service` (or your preferred name)
    - **Homepage URL**: `http://127.0.0.1:3000` (for local development)
    - **Authorization callback URL**: `http://127.0.0.1:3000/ops/oauth-callback`
4.  Click **Register application**.
5.  On the application page, you will see the **Client ID**. Copy this value to `GITHUB_CLIENT_ID` in your `.env` file.
6.  Click **Generate a new client secret**. Copy this value to `GITHUB_CLIENT_SECRET` in your `.env` file.

#### Local Development

1.  **Clone the repository.**
2.  **Set up configuration:**
    Copy `env.example` to `.env`:
    ```bash
    cp env.example .env
    ```
    Populate the `.env` file with your GitHub App credentials and test organization/team details.
    
    Also configure the Redis URL from the docker image (leave as is if default was used) and the API tokens that should be allowed for authentication requests.
3.  **Run a local valkey:**
    ```bash
    docker run --rm -p6379:6379 --name some-valkey valkey/valkey
    ```
4.  **Run the application:**
    ```bash
    cargo run
    ```
    The server typically starts on `http://127.0.0.1:3000`.
5.  **Inject a test request:**
    ```bash
    curl -v -X PUT -H "content-type: application/json" -d '{"ned": "fred"}' "http://127.0.0.1:3000/request-auth/$(dd if=/dev/random bs=32 count=1 | base64 -w0 | tr '+/' '-_' | tr -d '=')"
    ```

## For DevOps

### Deployment Guide

The service is compiled as a single binary and configured exclusively via environment variables.

#### Build

To build a release binary:
```bash
cargo build --release
```
The binary will be located at `target/release/hc-auth-server`.

#### Configuration

All configuration is handled via environment variables.

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GITHUB_CLIENT_ID` | Client ID from your GitHub OAuth App | - | Yes |
| `GITHUB_CLIENT_SECRET` | Client Secret from your GitHub OAuth App | - | Yes |
| `GITHUB_ORG` | GitHub Organization name for access control | - | Yes |
| `GITHUB_TEAM` | GitHub Team slug within the org | - | Yes |
| `SESSION_SECRET` | Secret key for signing session cookies (min 64 chars recommended) | - | Yes |
| `HOST` | Interface to bind to | `127.0.0.1` | No |
| `PORT` | Port to listen on | `3000` | No |
| `RUST_LOG` | Tracing log level filter | `hc_auth_server=debug,tower_http=debug` | No |

Helper for generating session secret:

```sh
dd if=/dev/random bs=66 count=1 | base64 -w0
```

#### Health Checks & Monitoring

- **Logs**: The application outputs structured logs to stdout using `tracing`. Log level can be adjusted with `RUST_LOG`.
- **Health**: Standard HTTP health checks can be performed against the root endpoint `/` (returns public home page) or you may want to ensure the process accepts TCP connections. Note that the restricted operations area is now under `/ops-auth`.

### Operational Notes

### API Documentation

The server provides three sets of routes: Client, Operations (Ops), and Admin (API).

#### Client Routes
These routes are used by clients wishing to authenticate.

| Route | Method | Description | Path Elements | Query Params | Error Codes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/now` | `GET` | Get a challenge payload for signing. | None | None | 500 (Server Error) |
| `/request-auth/{key}` | `PUT` | Request authentication for a public key. | `{key}`: Base64URL encoded Ed25519 public key. | None | 401 (Invalid Key), 429 (Too many pending), 500 (Storage Error) |
| `/authenticate` | `PUT` | Finalize authentication with a signed challenge. | None | None | 401 (Unauthorized/Invalid Sig), 500 (Storage Error) |

**Notes on `/authenticate`**:
- Requires `Content-Type: application/octet-stream`.
- Body must be a UTF-8 JSON string containing `pubKey`, `signature`, and `payload` (all Base64URL encoded).
- `payload` must be exactly what was returned by `/now`.

#### Operations (Ops) Routes
These routes are used by administrators via the web interface.

| Route | Method | Description | Path Elements | Query Params | Error Codes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/` | `GET` | Home page. | None | `error`: Optional error message. | 500 (Render Error) |
| `/ops/auth` | `GET` | Management dashboard (requires login). | None | `view_key`: Optional key to view details. | 302 (Redirect if not logged in) |
| `/ops/approve` | `POST` | Approve a pending request (requires CSRF).| None | None | 302 (Redirect on success/error) |
| `/ops/block` | `POST` | Block a request (requires CSRF). | None | None | 302 (Redirect on success/error) |
| `/ops/logout` | `GET` | Log out from the management session. | None | None | 302 (Redirect to `/`) |
| `/ops/oauth-login` | `GET` | Initiate GitHub OAuth login. | None | None | 302 (Redirect to GitHub) |
| `/ops/oauth-callback`| `GET` | GitHub OAuth callback handler. | None | `code`, `state` | 302 (Redirect to home/error) |

#### Admin (API) Routes
These routes provide programmatic access to management functions. All routes require an `Authorization: Bearer <token>` header.

| Route | Method | Description | Path Elements | Query Params | Error Codes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/list` | `GET` | List all pending request keys. | None | None | 401 (Unauthorized), 500 (Server Error) |
| `/api/get/{key}` | `GET` | Get details for a specific key. | `{key}`: Base64URL encoded public key. | None | 401 (Unauthorized), 404 (Not Found) |
| `/api/approve/{key}`| `POST`| Approve a pending request. | `{key}`: Base64URL encoded public key. | None | 401 (Unauthorized), 500 (Server Error) |
| `/api/reject/{key}` | `POST`| Reject a pending request. | `{key}`: Base64URL encoded public key. | None | 401 (Unauthorized), 500 (Server Error) |

---

- Ensure the `SESSION_SECRET` is kept secure and rotated if compromised.
- The service is stateless regarding session data (stored in signed cookies), allowing for horizontal scaling behind a load balancer, provided cookie sticking/affinity is not required by `tower-cookies` (it is not, as state is client-side).
