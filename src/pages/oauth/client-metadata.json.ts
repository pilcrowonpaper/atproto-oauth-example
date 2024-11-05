import {
	getOAuthKeyPair,
	productionOAuthClientId,
	productionOAuthRedirectURI,
} from "../../lib/oauth";
import { createECDSAPublicKeyJWKWithId } from "../../lib/utils";

export async function GET(): Promise<Response> {
	const keyPair = await getOAuthKeyPair();
	if (keyPair === null) {
		return new Response(null, {
			status: 404,
		});
	}
	const publicKeyJWK = await createECDSAPublicKeyJWKWithId(keyPair.publicKey, keyPair.id);
	const data = JSON.stringify({
		client_id: productionOAuthClientId(),
		application_type: "web",
		grant_types: ["authorization_code", "refresh_token"],
		scope: ["atproto", "transition:generic"].join(" "),
		response_type: ["code"],
		redirect_uris: [productionOAuthRedirectURI()],
		token_endpoint_auth_method: "private_key_jwt",
		token_endpoint_auth_signing_alg: "ES256",
		dpop_bound_access_tokens: true,
		jwks: {
			keys: [publicKeyJWK],
		},
	});
	const response = new Response(data);
	response.headers.set("Content-Type", "application/json");
	return response;
}
