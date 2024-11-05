import { decodeBase64 } from "@oslojs/encoding";
import { createLocalhostATProtoOAuthClient, ATProtoOAuthClient } from "./atproto";
import { envvar, joinURIBaseAndPath } from "./utils";

import type { CryptoKeyPairWithId } from "./atproto";

export function productionOAuthClientId(): string {
	const publicURL = envvar("PUBLIC_URL");
	if (publicURL === null) {
		throw new Error("Public URL not defined");
	}
	return joinURIBaseAndPath(publicURL, "/oauth/client-metadata.json");
}

export function productionOAuthRedirectURI(): string {
	const publicURL = envvar("PUBLIC_URL");
	if (publicURL === null) {
		throw new Error("Public URL not defined");
	}
	return joinURIBaseAndPath(publicURL, "/login/callback");
}

export async function createOAuthClient(
	authorizationServerIssuer: string,
): Promise<ATProtoOAuthClient> {
	if (import.meta.env.DEV) {
		const client = createLocalhostATProtoOAuthClient(
			authorizationServerIssuer,
			"http://[::1]:4321/login/callback",
			["transition:generic"],
		);
		return client;
	}
	const keyPair = await getOAuthKeyPair();
	if (keyPair === null) {
		throw new Error("OAuth key not defined");
	}
	const client = new ATProtoOAuthClient(
		authorizationServerIssuer,
		productionOAuthClientId(),
		productionOAuthRedirectURI(),
		keyPair,
	);
	return client;
}

const getOAuthKeyPairPromise = new Promise<CryptoKeyPairWithId | null>(async (resolve) => {
	const privateKeyBase64 = envvar("OAUTH_PRIVATE_KEY");
	const publicKeyBase64 = envvar("OAUTH_PUBLIC_KEY");
	const keyPairId = envvar("OAUTH_KEY_PAIR_ID");

	if (privateKeyBase64 === null || publicKeyBase64 === null || keyPairId === null) {
		return resolve(null);
	}

	const derPrivateKey = decodeBase64(privateKeyBase64);
	const privateKey = await crypto.subtle.importKey(
		"pkcs8",
		derPrivateKey,
		{
			name: "ECDSA",
			namedCurve: "P-256",
		},
		true,
		["sign"],
	);

	const derPublicKey = decodeBase64(publicKeyBase64);
	const publicKey = await crypto.subtle.importKey(
		"spki",
		derPublicKey,
		{
			name: "ECDSA",
			namedCurve: "P-256",
		},
		true,
		["verify"],
	);

	const keyPair: CryptoKeyPairWithId = {
		privateKey,
		publicKey,
		id: keyPairId,
	};
	return resolve(keyPair);
});

export async function getOAuthKeyPair(): Promise<CryptoKeyPairWithId | null> {
	return getOAuthKeyPairPromise;
}
