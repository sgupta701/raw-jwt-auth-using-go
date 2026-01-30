Raw JWT Implementation in Go

a bare-metal implementation of JWT authentication to understand the internal mechanics of:

- Token Issuance (HMAC Signing)
- Middleware Verification patterns
- manual HTTP Header parsing
- refresh token

Note: The secret key is currently hardcoded for demonstration purposes. In a production environment, this would be moved to an .env file.