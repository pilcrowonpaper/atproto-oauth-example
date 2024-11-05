import { decodeBase64 } from "@oslojs/encoding";
import {
    createLocalhostATProtoOAuthClient,
    ATProtoOAuthClient,
} from "./atproto";
import { joinURIBaseAndPath } from "./utils";

import type { CryptoKeyPairWithId } from "./atproto";

// TODO: Updated domain
export function productionOAuthClientId(): string {
    if (import.meta.env.PUBLIC_URL === undefined) {
        throw new Error("Public URL not defined");
    }
    return joinURIBaseAndPath(
        import.meta.env.PUBLIC_URL,
        "/oauth/client-metadata.json"
    );
}

export function productionOAuthRedirectURI(): string {
    if (import.meta.env.PUBLIC_URL === undefined) {
        throw new Error("Public URL not defined");
    }
    return joinURIBaseAndPath(import.meta.env.PUBLIC_URL, "/login/callback");
}

export async function createOAuthClient(
    authorizationServerIssuer: string
): Promise<ATProtoOAuthClient> {
    if (import.meta.env.DEV) {
        const client = createLocalhostATProtoOAuthClient(
            authorizationServerIssuer,
            "http://[::1]:4321/login/callback",
            ["transition:generic"]
        );
        return client;
    }
    const keyPair = await getOAuthKeyPair();
    if (keyPair === null) {
        throw new Error("OAuth key not defined");
    }
    // TODO: Updated domain
    const client = new ATProtoOAuthClient(
        authorizationServerIssuer,
        productionOAuthClientId(),
        productionOAuthRedirectURI(),
        keyPair
    );
    return client;
}

const getOAuthKeyPairPromise = new Promise<CryptoKeyPairWithId | null>(
    async (resolve) => {
        if (import.meta.env.OAUTH_PRIVATE_KEY === undefined) {
            return resolve(null);
        }
        if (import.meta.env.OAUTH_PUBLIC_KEY === undefined) {
            return resolve(null);
        }
        if (import.meta.env.OAUTH_KEY_PAIR_ID === undefined) {
            return resolve(null);
        }

        const derPrivateKey = decodeBase64(import.meta.env.OAUTH_PRIVATE_KEY);
        const privateKey = await crypto.subtle.importKey(
            "pkcs8",
            derPrivateKey,
            {
                name: "ECDSA",
                namedCurve: "P-256",
            },
            true,
            ["sign"]
        );

        const derPublicKey = decodeBase64(import.meta.env.OAUTH_PUBLIC_KEY);
        const publicKey = await crypto.subtle.importKey(
            "spki",
            derPublicKey,
            {
                name: "ECDSA",
                namedCurve: "P-256",
            },
            true,
            ["verify"]
        );

        const keyPair: CryptoKeyPairWithId = {
            privateKey,
            publicKey,
            id: import.meta.env.OAUTH_KEY_PAIR_ID,
        };
        return resolve(keyPair);
    }
);

export async function getOAuthKeyPair(): Promise<CryptoKeyPairWithId | null> {
    return getOAuthKeyPairPromise;
}
