import { bearer } from "@elysiajs/bearer";
import type { Elysia } from "elysia";
import { type JWTPayload, createRemoteJWKSet, jwtVerify } from "jose";

/**
 * Options for configuring the OAuth2 Resource Server
 */
export interface OAuth2ResourceServerOptions {
	/** URL to the JWKS endpoint (typically ends with /.well-known/jwks.json) */
	jwksUri: string;
	/** Expected issuer value (must match the JWT's iss claim) */
	issuer: string;
	/** Expected audience value(s) (must be included in the JWT's aud claim) */
	audience?: string | string[];
	/** List of scopes that must be present in the token */
	requiredScopes?: string[];
	/** Options for JWKS retrieval and caching */
	jwksOptions?: {
		/** Max age of cached JWKS in milliseconds (default: 10 minutes) */
		cacheMaxAge?: number;
		/** Timeout for JWKS request in milliseconds (default: 5 seconds) */
		timeoutDuration?: number;
	};
}

/**
 * Creates an OAuth2 Resource Server middleware for Elysia
 *
 * @example
 * ```typescript
 * app.use(oauth2ResourceServer({
 *   jwksUri: 'https://auth.example.com/.well-known/jwks.json',
 *   issuer: 'https://auth.example.com',
 *   audience: 'my-api'
 * }))
 * ```
 */
export function oauth2ResourceServer(options: OAuth2ResourceServerOptions) {
	// Create JWKS client from the authorization server's jwks_uri
	const jwks = createRemoteJWKSet(new URL(options.jwksUri), {
		cacheMaxAge: options.jwksOptions?.cacheMaxAge,
		timeoutDuration: options.jwksOptions?.timeoutDuration,
	});

	return (app: Elysia) =>
		app.use(bearer()).derive(async ({ bearer }) => {
			// Handle missing token
			if (!bearer) {
				throw new Response(JSON.stringify({ error: "Unauthorized" }), {
					status: 401,
					headers: { "Content-Type": "application/json" },
				});
			}

			let payload: JWTPayload;
			try {
				// Verify token against JWKS with issuer and audience validation
				const result = await jwtVerify(bearer, jwks, {
					issuer: options.issuer,
					audience: options.audience,
				});
				payload = result.payload;
			} catch (error) {
				throw new Response(
					JSON.stringify({
						error: "Unauthorized",
						message:
							error instanceof Error
								? error.message
								: "Invalid token",
					}),
					{
						status: 401,
						headers: { "Content-Type": "application/json" },
					},
				);
			}

			// Optional scope validation
			if (options.requiredScopes?.length) {
				const tokenScopes =
					typeof payload.scope === "string"
						? payload.scope.split(" ")
						: [];

				const hasRequiredScopes = options.requiredScopes.every(
					(scope) => tokenScopes.includes(scope),
				);

				if (!hasRequiredScopes) {
					throw new Response(
						JSON.stringify({
							error: "Forbidden",
							message: "Insufficient scopes",
						}),
						{
							status: 403,
							headers: { "Content-Type": "application/json" },
						},
					);
				}
			}

			return { auth: payload };
		});
}
