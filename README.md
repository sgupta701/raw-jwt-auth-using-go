Raw jwt Implementation in go... 
creation of token, addition of middleware and reissuuing of access token using refresh tokens upon expiration...

a simple implementation of JWT authentication to understand the internal mechanics of:

- token issuance
- middleware verification patterns
- manual HTTP header parsing
- refresh tokens

secret key is currently hardcoded.. in a production environment, this would be moved to an .env file. 

**start the server**
    go run main.go

## API Usage

### login

    curl -X POST http://localhost:8000/login \ -d '{"username": "admin", "password": "password"}'


### auth
    curl -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" http:localhost:8000/home

### reissue access token

    curl -X POST http://localhost:8000/refresh \ -d '{"refresh_token": "<YOUR_REFRESH_TOKEN>"}'
