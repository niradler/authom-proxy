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

- Node.js (v14 or later)
- npm or yarn
- Docker and docker-compose (optional, for containerized deployment)

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/authom-proxy.git
   cd authom-proxy
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Create a `.env` file in the root directory and add your configuration:
   ```
   PORT=3000
   JWT_SECRET=your_jwt_secret
   ALLOWED_USERS=user1@example.com,user2@example.com
   GOOGLE_CLIENT_ID=your_google_client_id
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   # Add other provider credentials as needed
   ```

4. Build the project:
   ```
   npm run build
   ```

5. Start the server:
   ```
   npm start
   ```

### Docker Deployment

To deploy using Docker and docker-compose:

1. Ensure you have Docker and docker-compose installed.
2. Create a `.env` file as described in the Installation section.
3. Run:
   ```
   docker-compose up -d
   ```

## Usage

1. Configure your application to use Authom Proxy as an authentication middleware.
2. Direct users to `http://your-domain.com/auth/providers` to see available login options.
3. After successful authentication, users will be redirected to your application with an `X-Forwarded-User` header containing their email.

## Configuration

Authom Proxy can be configured using environment variables or a `authom-proxy.json` file. See the `src/config.ts` file for available options.

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
