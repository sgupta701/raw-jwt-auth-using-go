Raw jwt Implementation in go... 
creation of token, addition of middleware and reissuuing of access token using refresh tokens upon expiration...

a bare-metal implementation of JWT authentication to understand the internal mechanics of:

- token issuance
- middleware verification patterns
- manual HTTP header parsing
- refresh tokens

secret key is currently hardcoded.. in a production environment, this would be moved to an .env file.