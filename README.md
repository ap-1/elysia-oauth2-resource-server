# elysia-oauth2-resource-server

OAuth2 Resource Server middleware for Elysia, providing local JWT validation against JWKS endpoints. Inspired by the [`tower-oauth2-resource-server`](https://crates.io/crates/tower-oauth2-resource-server) crate for Rust.

[![NPM Version](https://img.shields.io/npm/v/elysia-oauth2-resource-server)](https://www.npmjs.com/package/elysia-oauth2-resource-server)
[![License](https://img.shields.io/npm/l/elysia-oauth2-resource-server)](https://github.com/ap-1/elysia-oauth2-resource-server/blob/main/LICENSE)

## Features

- Validates JWT tokens from OAuth2/OIDC providers
- JWKS-based signature validation
- Verifies issuer and audience claims
- Validates token scopes for authorization

## Installation

```bash
bun add elysia-oauth2-resource-server
```

## Quick Start

```ts
import { Elysia } from "elysia";
import { oauth2ResourceServer } from "elysia-oauth2-resource-server"

const app = new Elysia()
	.use(oauth2ResourceServer({
		jwksUri: 'https://auth.example.com/.well-known/jwks.json',
		issuer: 'https://auth.example.com',
		audience: 'my-api',
		requiredScopes: ['read:users']
	}))
	.get('/users', ({ auth }) => {
		// auth contains the validated JWT payload
		return { userId: auth.sub }
	})
	.listen(3000);

console.log("Server is listening at http://localhost:3000");
```

## API Reference

### `oauth2ResourceServer(options)`

Creates an OAuth2 Resource Server middleware that validates JWTs against a JWKS endpoint.

#### Options


| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `jwksUri` | `string` | Yes | The URL to the JWKS endpoint (typically ends with `/.well-known/jwks.json`) |
| `issuer` | `string` | Yes | The expected issuer claim value (must match the JWT's `iss` claim) |
| `audience` | `string \| string[]` | No | Expected audience(s) (must be included in the JWT's `aud` claim) |
| `requiredScopes` | `string[]` | No | List of scopes that must be present in the token |
| `jwksOptions` | `object` | No | Options for JWKS retrieval and caching |
| `jwksOptions.cacheMaxAge` | `number` | No | Max age of cached JWKS in milliseconds |
| `jwksOptions.timeoutDuration` | `number` | No | Timeout for JWKS request in milliseconds |

#### Returns

Adds an `auth` property to the request context, which contains the validated JWT payload.
