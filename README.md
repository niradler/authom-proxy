# Authom Proxy

Authom Proxy is an open-source authentication proxy service that simplifies the integration of various OAuth providers into your applications. It provides a unified interface for handling authentication across multiple platforms, making it easier to secure your services and manage user access.

## Features

- Support for multiple OAuth providers (Google, GitHub, Facebook, Twitter, LinkedIn, Microsoft, Apple, Amazon, Yahoo, Discord)
- Easy configuration through environment variables or a JSON file
- JWT-based session management
- Configurable allowed users list
- Docker and docker-compose support for easy deployment
- Traefik integration for reverse proxy and load balancing

## Getting Started

### Prerequisites

- Node.js 22 or later
- npm
- Docker and docker-compose (optional, for containerized deployment)

### Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/niradler/authom-proxy.git
   cd authom-proxy
   ```

2. Install dependencies:

   ```sh
   npm install
   ```

3. Create a `.env` file from `.env.example`. `PUBLIC_URL`, `JWT_SECRET`, `COOKIE_SECRET`, `ALLOWED_USERS`, and one OAuth provider are required. Secrets must be at least 32 characters. The process listens on `127.0.0.1` unless `BIND_HOST` is set. For several apps on one lab domain, set `COOKIE_DOMAIN` to that parent domain and list each app origin in `ALLOWED_REDIRECT_ORIGINS`.

4. Build and start:

   ```sh
   npm run build
   npm start
   ```

### Docker Deployment

To deploy using Docker and docker-compose:

1. Create a `.env` file as described in the Installation section.
2. Run `docker compose up -d --build`. The published port is bound to `127.0.0.1:8001`. Inside the container the process listens on `0.0.0.0` so a private Docker network can reach it. Attach the container to the Traefik network when the proxy runs in another container.
3. Point Traefik forward auth at `http://authom-proxy:3000/auth/session` and copy `X-Forwarded-User` into the upstream request. Set `TRUST_PROXY=1` when Traefik is the only proxy in front of this service. Leave the auth router itself outside the forward-auth middleware. A browser without a session is redirected to `/auth/login` and, after login, back to an origin listed in `ALLOWED_REDIRECT_ORIGINS`.

## Usage

1. Send users who need to sign in to `https://auth.lab.example/auth/login`.
2. After a successful login the browser receives an `HttpOnly` session cookie. With `COOKIE_DOMAIN` set, that cookie is sent to the other lab apps.
3. Forward-auth checks call `/auth/session`. Allowlisted users get `200` and `X-Forwarded-User`. Everyone else gets a login redirect, or `401` when the client asks for JSON. Return targets are limited to same-site paths and origins in `ALLOWED_REDIRECT_ORIGINS`.

## Supported Providers

Authom Proxy supports the following OAuth providers out of the box:

1. Google (tested)
2. GitHub
3. Facebook
4. Twitter
5. LinkedIn
6. Microsoft
7. Apple
8. Amazon
9. Yahoo
10. Discord

## Configuration

Authom Proxy can be configured using environment variables or a `authom-proxy.json` file. See the `src/config.ts` file for available options.

### Configuring Providers

To enable a provider, you need to set the corresponding environment variables or add them to your `authom-proxy.json` file. For example, to enable Google authentication:

1. Set the environment variables:

```sh
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

2. Alternatively, add the provider configuration to `authom-proxy.json`:

```json
{
  "providers": {
    "google": {
      "clientId": "your_google_client_id",
      "clientSecret": "your_google_client_secret",
      "authUrl": "https://accounts.google.com/o/oauth2/v2/auth",
      "tokenUrl": "https://oauth2.googleapis.com/token",
      "profileUrl": "https://www.googleapis.com/oauth2/v3/userinfo",
      "scope": "openid email"
    }
  }
}
```

Adding custom provider:
```json
{
  "providers": {
  "custom": {
    "authUrl": "https://customdomain.com/authorize",
    "tokenUrl": "https://customdomain.com/oauth2/token",
    "profileUrl": "https://customdomain.com/api/auth/userinfo",
      "scope": "email"
    }
  }
}
```

## Contributing

We welcome contributions to Authom Proxy! Please follow these steps to contribute:

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes and commit them with a clear commit message
4. Push your changes to your fork
5. Create a pull request to the main repository

Please ensure your code adheres to the existing style and includes appropriate tests.

## License

This project is licensed under the ISC License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.
