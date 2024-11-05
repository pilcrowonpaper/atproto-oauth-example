import { ObjectParser } from "@pilcrowjs/object-parser";
import type { APIContext } from "astro";
import {
	generateOAuthNonce,
	getATProtoAuthorizationServerMetadata,
	getAuthorizationServer,
	getPDSFromAccountDID,
	resolveATProtoHandle,
} from "../../lib/atproto";
import { createOAuthClient } from "../../lib/oauth";

export async function POST(context: APIContext): Promise<Response> {
	const data = await context.request.json();
	const parser = new ObjectParser(data);
	let handle: string;
	try {
		handle = parser.getString("handle");
	} catch {
		return new Response("Invalid data.", {
			status: 400,
		});
	}
	let did: string;
	try {
		did = await resolveATProtoHandle(handle);
	} catch (e) {
		console.log(e);
		return new Response("Invalid handle", {
			status: 400,
		});
	}

	const pdsEndpoint = await getPDSFromAccountDID(did);
	const authorizationServerEndpoint = await getAuthorizationServer(pdsEndpoint);
	const authorizationServerMetadata = await getATProtoAuthorizationServerMetadata(
		authorizationServerEndpoint,
	);
	const state = generateOAuthNonce();
	const codeVerifier = generateOAuthNonce();
	const oauthClient = await createOAuthClient(authorizationServerMetadata.issuer);
	const authorizationURL = await oauthClient.createAuthorizationURL(
		authorizationServerMetadata.pushedAuthorizationRequestEndpoint,
		authorizationServerMetadata.authorizationEndpoint,
		state,
		codeVerifier,
		["transition:generic"],
	);
	context.cookies.set("state", state, {
		httpOnly: true,
		path: "/",
		maxAge: 60 * 10,
		sameSite: "lax",
		secure: !import.meta.env.DEV,
	});
	context.cookies.set("code_verifier", codeVerifier, {
		httpOnly: true,
		path: "/",
		maxAge: 60 * 10,
		sameSite: "lax",
		secure: !import.meta.env.DEV,
	});
	context.cookies.set("issuer", authorizationServerMetadata.issuer, {
		httpOnly: true,
		path: "/",
		maxAge: 60 * 10,
		sameSite: "lax",
		secure: !import.meta.env.DEV,
	});
	context.cookies.set("did", did, {
		httpOnly: true,
		path: "/",
		maxAge: 60 * 10,
		sameSite: "lax",
		secure: !import.meta.env.DEV,
	});
	return new Response(authorizationURL.toString());
}
