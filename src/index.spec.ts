import { beforeEach, describe, expect, it, mock } from "bun:test";

beforeEach(() => {
	mock.restore();
	mock.module("jose", () => {
		return {
			createRemoteJWKSet: () => async () => ({}),
			jwtVerify: async () => ({
				payload: {
					sub: "123",
					iss: "https://auth.example.com",
					aud: "test-api",
					scope: "read:users write:users",
				},
				protectedHeader: { alg: "RS256" },
			}),
		};
	});
});

describe("oauth2ResourceServer", () => {
	it("should validate tokens and return auth object", async () => {
		const { Elysia } = await import("elysia");
		const { oauth2ResourceServer } = await import("../src/index");

		const app = new Elysia()
			.use(
				oauth2ResourceServer({
					jwksUri: "https://auth.example.com/.well-known/jwks.json",
					issuer: "https://auth.example.com",
					audience: "test-api",
				}),
			)
			.get("/test", ({ auth }) => {
				return { userId: auth.sub };
			});

		const response = await app.handle(
			new Request("http://localhost/test", {
				headers: {
					Authorization: "Bearer fake.token.here",
				},
			}),
		);

		const result = await response.json();
		expect(result).toEqual({ userId: "123" });
	});

	it("should return 401 when no token is provided", async () => {
		const { Elysia } = await import("elysia");
		const { oauth2ResourceServer } = await import("../src/index");

		const app = new Elysia()
			.use(
				oauth2ResourceServer({
					jwksUri: "https://auth.example.com/.well-known/jwks.json",
					issuer: "https://auth.example.com",
				}),
			)
			.get("/test", ({ auth }) => {
				return { userId: auth.sub };
			});

		const response = await app.handle(new Request("http://localhost/test"));

		expect(response.status).toBe(401);
	});

	it("should return 403 if required scopes are missing", async () => {
		mock.restore();
		mock.module("jose", () => {
			return {
				createRemoteJWKSet: () => async () => ({}),
				jwtVerify: async () => ({
					payload: {
						sub: "123",
						iss: "https://auth.example.com",
						aud: "test-api",
						scope: "read:users", // does not include write:users
					},
					protectedHeader: { alg: "RS256" },
				}),
			};
		});

		const { Elysia } = await import("elysia");
		const { oauth2ResourceServer } = await import("../src/index");

		const app = new Elysia()
			.use(
				oauth2ResourceServer({
					jwksUri: "https://auth.example.com/.well-known/jwks.json",
					issuer: "https://auth.example.com",
					requiredScopes: ["read:users", "write:users"],
				}),
			)
			.get("/test", ({ auth }) => {
				return { userId: auth.sub };
			});

		const response = await app.handle(
			new Request("http://localhost/test", {
				headers: {
					Authorization: "Bearer fake.token.here",
				},
			}),
		);

		expect(response.status).toBe(403);

		const result = await response.json();
		expect(result).toEqual({
			error: "Forbidden",
			message: "Insufficient scopes",
		});
	});

	it("should return 401 if token verification fails", async () => {
		mock.restore();
		mock.module("jose", () => {
			return {
				createRemoteJWKSet: () => async () => ({}),
				jwtVerify: async () => {
					// simulate verification failure
					throw new Error("Invalid signature");
				},
			};
		});

		const { Elysia } = await import("elysia");
		const { oauth2ResourceServer } = await import("../src/index");

		const app = new Elysia()
			.use(
				oauth2ResourceServer({
					jwksUri: "https://auth.example.com/.well-known/jwks.json",
					issuer: "https://auth.example.com",
				}),
			)
			.get("/test", ({ auth }) => {
				return { userId: auth.sub };
			});

		const response = await app.handle(
			new Request("http://localhost/test", {
				headers: {
					Authorization: "Bearer fake.token.here",
				},
			}),
		);

		expect(response.status).toBe(401);

		const result = await response.json();
		expect(result).toEqual({
			error: "Unauthorized",
			message: "Invalid signature",
		});
	});
});
