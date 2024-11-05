import {
	fetchProtectedResourceRequestWithDPOP,
	getATProtoAuthorizationServerMetadata,
	getPDSFromAccountDID,
} from "../../lib/atproto";
import { createOAuthClient } from "../../lib/oauth";
import { joinURIBaseAndPath, readAllStreamWithLimit } from "../../lib/utils";
import { ObjectParser } from "@pilcrowjs/object-parser";

import type { APIContext } from "astro";
import type { ATProtoOAuthTokens } from "../../lib/atproto";

export async function GET(context: APIContext): Promise<Response> {
	const storedState = context.cookies.get("state")?.value ?? null;
	const codeVerifier = context.cookies.get("code_verifier")?.value ?? null;
	const storedIssuer = context.cookies.get("issuer")?.value ?? null;
	const storedDID = context.cookies.get("did")?.value ?? null;
	if (
		storedState === null ||
		codeVerifier === null ||
		storedIssuer === null ||
		storedDID === null
	) {
		return new Response("invalid request", {
			status: 400,
		});
	}
	const code = context.url.searchParams.get("code");
	const state = context.url.searchParams.get("state");
	const issuer = context.url.searchParams.get("iss");
	if (code === null || state === null || issuer === null) {
		return new Response("invalid request", {
			status: 400,
		});
	}
	if (storedState !== state || storedIssuer !== issuer) {
		return new Response("invalid request", {
			status: 400,
		});
	}
	const authorizationServerMetadata = await getATProtoAuthorizationServerMetadata(issuer);

	const dpopKeyPair = await crypto.subtle.generateKey(
		{
			name: "ECDSA",
			namedCurve: "P-256",
		},
		true,
		["sign", "verify"],
	);

	const oauthClient = await createOAuthClient(authorizationServerMetadata.issuer);
	let tokens: ATProtoOAuthTokens;
	let authorizationServerDPOPNonce: string | null;
	try {
		[tokens, authorizationServerDPOPNonce] = await oauthClient.validateAuthorizationCode(
			authorizationServerMetadata.tokenEndpoint,
			dpopKeyPair,
			code,
			codeVerifier,
		);
	} catch (e) {
		console.log(e);
		return new Response("invalid request");
	}
	if (storedDID !== tokens.did) {
		return new Response("invalid request", {
			status: 400,
		});
	}
	if (tokens.refreshToken !== null) {
		// Test refresh token
		[tokens] = await oauthClient.refreshAccessToken(
			authorizationServerMetadata.tokenEndpoint,
			dpopKeyPair,
			tokens.refreshToken,
			authorizationServerDPOPNonce,
		);
	}

	const pdsEndpoint = await getPDSFromAccountDID(tokens.did);

	const url = new URL(joinURIBaseAndPath(pdsEndpoint, "/xrpc/app.bsky.actor.getProfile"));
	url.searchParams.set("actor", tokens.did);
	const profileRequest = new Request(url);
	const [profileResponse] = await fetchProtectedResourceRequestWithDPOP(
		dpopKeyPair,
		authorizationServerMetadata.issuer,
		tokens.accessToken,
		profileRequest,
		null,
	);
	if (profileResponse.body === null) {
		throw new Error("Unexpected response");
	}
	const profileResultBytes = await readAllStreamWithLimit(profileResponse.body, 1024 * 64);
	const profileResult = JSON.parse(new TextDecoder().decode(profileResultBytes));
	const profileResultParser = new ObjectParser(profileResult);
	const profile = {
		did: profileResultParser.getString("did"),
		display_name: profileResultParser.getString("displayName"),
		handle: profileResultParser.getString("handle"),
	};
	return new Response(JSON.stringify(profile, null, 2));
}
