import { ObjectParser } from "@pilcrowjs/object-parser";
import {
    getECDSAPublicKeyJWK,
    joinURIBaseAndPath,
    readAllStreamWithLimit,
} from "./utils";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";
import { createJWTSignatureMessage, encodeJWT } from "@oslojs/jwt";

export async function resolveATProtoHandle(handle: string): Promise<string> {
    const txtParams = new URLSearchParams();
    txtParams.set("name", `_atproto.${handle}`);
    txtParams.set("type", "TXT");
    const txtRequest = new Request(
        "https://cloudflare-dns.com/dns-query" + "?" + txtParams.toString()
    );
    txtRequest.headers.set("Accept", "application/dns-json");
    const txtFetchPromise = fetch(txtRequest, {
        signal: AbortSignal.timeout(5000),
    });
    const wellknownFetchPromise = fetch(
        joinURIBaseAndPath(`https://${handle}`, "/.well-known/atproto-did"),
        {
            signal: AbortSignal.timeout(5000),
        }
    );

    const [txtFetchResult, wellknownFetchResult] = await Promise.allSettled([
        txtFetchPromise,
        wellknownFetchPromise,
    ]);
    if (txtFetchResult.status === "fulfilled") {
        if (
            txtFetchResult.value.status === 200 &&
            txtFetchResult.value.body !== null
        ) {
            // 32KB limit
            const resolverResultBytes = await readAllStreamWithLimit(
                txtFetchResult.value.body,
                1024 * 32
            );
            const resolverResult = JSON.parse(
                new TextDecoder().decode(resolverResultBytes)
            );
            const resolverResultParser = new ObjectParser(resolverResult);
            if (resolverResultParser.has("Answer")) {
                const dnsRecord = resolverResultParser.getString(
                    "Answer",
                    "0",
                    "data"
                );
                const did = parseATProtoTXTDNSRecord(dnsRecord);
                return did;
            }
        }
        if (txtFetchResult.value.body !== null) {
            txtFetchResult.value.body.cancel();
        }
    }

    if (wellknownFetchResult.status === "fulfilled") {
        if (
            wellknownFetchResult.value.status === 200 &&
            wellknownFetchResult.value.body !== null
        ) {
            // 32KB limit
            const wellknownResultBytes = await readAllStreamWithLimit(
                wellknownFetchResult.value.body,
                1024 * 32
            );
            const did = new TextDecoder().decode(wellknownResultBytes);
            return did;
        }
        if (wellknownFetchResult.value.body !== null) {
            wellknownFetchResult.value.body.cancel();
        }
    }
    throw new Error("Failed to resolve handle");
}

function parseATProtoTXTDNSRecord(record: string): string {
    if (!record.startsWith('"') || !record.endsWith('"')) {
        throw new Error("Unexpected record value");
    }
    const keyValue = record.slice(1, -1);
    const parts = keyValue.split("=");
    if (parts.length !== 2) {
        throw new Error("Unexpected record value");
    }
    if (parts[0] !== "did") {
        throw new Error("Unexpected record value");
    }
    return parts[1];
}

export async function getPDSFromAccountDID(did: string): Promise<string> {
    let pdsEndpoint: string;
    if (did.startsWith("did:plc:")) {
        pdsEndpoint = await getPDSFromAccountPLCDID(did);
    } else if (did.startsWith("did:web:")) {
        pdsEndpoint = await getPDSFromAccountWebDID(did);
    } else {
        throw new Error("Unknown DID format");
    }
    return pdsEndpoint;
}

export async function getPDSFromAccountWebDID(did: string): Promise<string> {
    const prefix = "did:web:";
    if (!did.startsWith(prefix)) {
        throw new Error("Invalid Web DID");
    }
    let target = did.slice(prefix.length);
    target = target.replaceAll(":", "/");
    target = decodeURIComponent(target);

    const response = await fetch(
        joinURIBaseAndPath(`https://${target}`, "/.well-known/did.json"),
        {
            signal: AbortSignal.timeout(5000),
        }
    );
    if (!response.ok) {
        if (response.body !== null) {
            response.body.cancel();
        }
        throw new Error("Invalid DID");
    }
    if (response.body === null) {
        throw new Error("Unexpected response");
    }
    // 32KB limit
    const resultBytes = await readAllStreamWithLimit(response.body, 1024 * 32);
    const result = JSON.parse(new TextDecoder().decode(resultBytes));
    const resultParser = new ObjectParser(result);
    const serviceResults = resultParser.getArray("service");
    for (let i = 0; i < serviceResults.length; i++) {
        const serviceResultParser = new ObjectParser(serviceResults[i]);
        if (serviceResultParser.getString("id") === "#atproto_pds") {
            return serviceResultParser.getString("serviceEndpoint");
        }
    }
    throw new Error("Failed to get PDS");
}

export async function getPDSFromAccountPLCDID(did: string): Promise<string> {
    const response = await fetch(
        joinURIBaseAndPath("https://plc.directory", did),
        {
            signal: AbortSignal.timeout(5000),
        }
    );
    if (!response.ok) {
        if (response.body !== null) {
            response.body.cancel();
        }
        throw new Error("Invalid DID");
    }
    if (response.body === null) {
        throw new Error("Unexpected response");
    }
    // 32KB limit
    const resultBytes = await readAllStreamWithLimit(response.body, 1024 * 32);
    const result = JSON.parse(new TextDecoder().decode(resultBytes));
    const resultParser = new ObjectParser(result);
    const serviceResults = resultParser.getArray("service");
    for (let i = 0; i < serviceResults.length; i++) {
        const serviceResultParser = new ObjectParser(serviceResults[i]);
        if (serviceResultParser.getString("id") === "#atproto_pds") {
            return serviceResultParser.getString("serviceEndpoint");
        }
    }
    throw new Error("Failed to get PDS");
}

export async function getAuthorizationServer(
    pdsEndpoint: string
): Promise<string> {
    const response = await fetch(
        joinURIBaseAndPath(pdsEndpoint, "/.well-known/oauth-protected-resource")
    );
    if (!response.ok) {
        if (response.body !== null) {
            response.body.cancel();
        }
        throw new Error("Failed to get PDS authorization server");
    }
    if (response.body === null) {
        throw new Error("Unexpected response");
    }
    // 32KB limit
    const resultBytes = await readAllStreamWithLimit(response.body, 1024 * 32);
    const result = JSON.parse(new TextDecoder().decode(resultBytes));
    const resultParser = new ObjectParser(result);
    const authorizationServer = resultParser.getString(
        "authorization_servers",
        "0"
    );
    return authorizationServer;
}

export async function getATProtoAuthorizationServerMetadata(
    issuer: string
): Promise<ATProtoAuthorizationServerMetadata> {
    const metadataURL = joinURIBaseAndPath(
        issuer,
        "/.well-known/oauth-authorization-server"
    );
    const response = await fetch(metadataURL);
    if (!response.ok) {
        if (response.body !== null) {
            response.body.cancel();
        }
        throw new Error("Failed to get authorization server meta data");
    }
    if (response.body === null) {
        throw new Error("Unexpected response");
    }
    // 32KB limit
    const resultBytes = await readAllStreamWithLimit(response.body, 1024 * 32);
    const result = JSON.parse(new TextDecoder().decode(resultBytes));
    const resultParser = new ObjectParser(result);
    const metadataIssuer = resultParser.getString("issuer");
    if (issuer !== metadataIssuer) {
        throw new Error("Invalid metadata");
    }
    const pushedAuthorizationRequestEndpoint = resultParser.getString(
        "pushed_authorization_request_endpoint"
    );
    const tokenEndpoint = resultParser.getString("token_endpoint");
    const authorizationEndpoint = resultParser.getString(
        "authorization_endpoint"
    );
    const metadata: ATProtoAuthorizationServerMetadata = {
        issuer,
        pushedAuthorizationRequestEndpoint,
        tokenEndpoint,
        authorizationEndpoint,
    };
    return metadata;
}

interface ATProtoAuthorizationServerMetadata {
    issuer: string;
    pushedAuthorizationRequestEndpoint: string;
    tokenEndpoint: string;
    authorizationEndpoint: string;
}

export function createLocalhostATProtoOAuthClient(
    authorizationServerIssuer: string,
    redirectURI: string,
    allowedOptionalScopes: string[]
): ATProtoOAuthClient {
    const clientIdParams = new URLSearchParams();
    clientIdParams.set("redirect_uri", redirectURI);
    clientIdParams.set(
        "scope",
        ["atproto", ...allowedOptionalScopes].join(" ")
    );
    const clientId = "http://localhost" + "?" + clientIdParams.toString();
    const client = new ATProtoOAuthClient(
        authorizationServerIssuer,
        clientId,
        redirectURI,
        null
    );
    return client;
}

export interface CryptoKeyPairWithId extends CryptoKeyPair {
    id: string;
}

export class ATProtoOAuthClient {
    private authorizationServerIssuer: string;
    private clientId: string;
    private redirectURI: string;
    private keyPair: CryptoKeyPairWithId | null;

    constructor(
        authorizationServerIssuer: string,
        clientId: string,
        redirectURI: string,
        keyPair: CryptoKeyPairWithId | null
    ) {
        this.authorizationServerIssuer = authorizationServerIssuer;
        this.clientId = clientId;
        this.redirectURI = redirectURI;
        this.keyPair = keyPair;
    }

    public async createAuthorizationURL(
        pushedAuthorizationRequestEndpoint: string,
        authorizationEndpoint: string,
        state: string,
        codeVerifier: string,
        optionalScopes: string[]
    ): Promise<URL> {
        const codeChallengeBytes = await sha256(
            new TextEncoder().encode(codeVerifier)
        );
        const codeChallenge = encodeBase64urlNoPadding(codeChallengeBytes);
        const scopeParameter = ["atproto", ...optionalScopes].join(" ");
        const body = new URLSearchParams();
        body.set("response_type", "code");
        body.set("client_id", this.clientId);
        body.set("redirect_uri", this.redirectURI);
        body.set("state", state);
        body.set("code_challenge_method", "S256");
        body.set("code_challenge", codeChallenge);
        body.set("scope", scopeParameter);
        if (this.keyPair !== null) {
            const clientAssertion = await createClientAssertion(
                this.keyPair,
                this.clientId,
                this.authorizationServerIssuer
            );
            body.set(
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            );
            body.set("client_assertion", clientAssertion);
        }
        const request = new Request(pushedAuthorizationRequestEndpoint, {
            method: "POST",
            body,
        });
        request.headers.set(
            "Content-Type",
            "application/x-www-form-urlencoded"
        );
        request.headers.set("Accept", "application/json");
        request.headers.set("User-Agent", "demo");
        const response = await fetch(request, {
            signal: AbortSignal.timeout(5000),
        });
        if (!response.ok) {
            throw new Error("Failed to create authorization request");
        }
        if (response.body === null) {
            throw new Error("Unexpected response");
        }
        const resultBytes = await readAllStreamWithLimit(
            response.body,
            1024 * 32
        );
        const result = JSON.parse(new TextDecoder().decode(resultBytes));
        const resultParser = new ObjectParser(result);
        const requestURI = resultParser.getString("request_uri");

        const authorizationRequestURL = new URL(authorizationEndpoint);
        authorizationRequestURL.searchParams.set("client_id", this.clientId);
        authorizationRequestURL.searchParams.set("request_uri", requestURI);
        return authorizationRequestURL;
    }

    public async validateAuthorizationCode(
        tokenEndpoint: string,
        dpopKeyPair: CryptoKeyPair,
        code: string,
        codeVerifier: string
    ): Promise<[tokens: ATProtoOAuthTokens, dpopNonce: string | null]> {
        let body = new URLSearchParams();
        body.set("grant_type", "authorization_code");
        body.set("client_id", this.clientId);
        body.set("code", code);
        body.set("code_verifier", codeVerifier);
        body.set("redirect_uri", this.redirectURI);
        let request = new Request(tokenEndpoint, {
            method: "POST",
            body,
        });
        request.headers.set(
            "Content-Type",
            "application/x-www-form-urlencoded"
        );
        request.headers.set("Accept", "application/json");
        const [successfulResponse, dpopNonce] = await sendOAuthRequest(
            dpopKeyPair,
            request,
            null
        );
        if (successfulResponse.body === null) {
            throw new Error("Unexpected response");
        }
        const resultBytes = await readAllStreamWithLimit(
            successfulResponse.body,
            1024 * 32
        );
        const result = JSON.parse(new TextDecoder().decode(resultBytes));
        const tokens = parseOAuthTokensResult(result);
        return [tokens, dpopNonce];
    }

    public async refreshAccessToken(
        tokenEndpoint: string,
        dpopKeyPair: CryptoKeyPair,
        refreshToken: string,
        dpopNonce: string | null
    ): Promise<[tokens: ATProtoOAuthTokens, dpopNonce: string | null]> {
        let body = new URLSearchParams();
        body.set("grant_type", "refresh_token");
        body.set("client_id", this.clientId);
        body.set("refresh_token", refreshToken);
        body.set("redirect_uri", this.redirectURI);
        let request = new Request(tokenEndpoint, {
            method: "POST",
            body,
        });
        request.headers.set(
            "Content-Type",
            "application/x-www-form-urlencoded"
        );
        request.headers.set("Accept", "application/json");
        const [successfulResponse, newDPOPNonce] = await sendOAuthRequest(
            dpopKeyPair,
            request,
            dpopNonce
        );
        if (newDPOPNonce !== null) {
            dpopNonce = newDPOPNonce;
        }
        if (successfulResponse.body === null) {
            throw new Error("Unexpected response");
        }
        const resultBytes = await readAllStreamWithLimit(
            successfulResponse.body,
            1024 * 32
        );
        const result = JSON.parse(new TextDecoder().decode(resultBytes));
        const tokens = parseOAuthTokensResult(result);
        return [tokens, dpopNonce];
    }
}

function parseOAuthTokensResult(result: unknown): ATProtoOAuthTokens {
    let resultParser = new ObjectParser(result);

    const did = resultParser.getString("sub");

    const accessToken = resultParser.getString("access_token");

    let accessTokenExpiresInSeconds: number | null = null;
    if (resultParser.has("refresh_token")) {
        accessTokenExpiresInSeconds = resultParser.getNumber("expires_in");
    }
    let refreshToken: string | null = null;
    if (resultParser.has("refresh_token")) {
        refreshToken = resultParser.getString("refresh_token");
    }
    let accessTokenExpiresAt: Date | null = null;
    if (accessTokenExpiresInSeconds !== null) {
        accessTokenExpiresAt = new Date(
            Date.now() + accessTokenExpiresInSeconds * 1000
        );
    }
    const tokens: ATProtoOAuthTokens = {
        did,
        accessToken,
        accessTokenExpiresAt,
        refreshToken,
    };
    return tokens;
}

export interface ATProtoOAuthTokens {
    did: string;
    accessToken: string;
    accessTokenExpiresAt: Date | null;
    refreshToken: string | null;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
    const digest = await crypto.subtle.digest("SHA-256", data);
    const digestBytes = new Uint8Array(digest);
    return digestBytes;
}

export function generateOAuthNonce(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const state = encodeBase64urlNoPadding(bytes);
    return state;
}

async function createClientAssertion(
    keyPair: CryptoKeyPairWithId,
    clientId: string,
    authorizationServerIssuer: string
): Promise<string> {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    const headerJSON = JSON.stringify({
        typ: "JWT",
        alg: "ES256",
        kid: keyPair.id,
    });
    const issuedAtUnix = Math.floor(Date.now() / 1000);
    const payloadJSON = JSON.stringify({
        iss: clientId,
        sub: clientId,
        aud: authorizationServerIssuer,
        jti: encodeBase64urlNoPadding(bytes),
        iat: issuedAtUnix,
        exp: issuedAtUnix + 60,
    });
    const message = createJWTSignatureMessage(headerJSON, payloadJSON);
    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: "SHA-256",
        },
        keyPair.privateKey,
        message
    );
    const dpop = encodeJWT(headerJSON, payloadJSON, new Uint8Array(signature));
    return dpop;
}

export async function createDPOP(
    keyPair: CryptoKeyPair,
    requestMethod: string,
    requestURL: string,
    nonce: string | null,
    attributes: object
): Promise<string> {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    const publicKeyJWK = await getECDSAPublicKeyJWK(keyPair.publicKey);
    const headerJSON = JSON.stringify({
        typ: "dpop+jwt",
        alg: "ES256",
        jwk: publicKeyJWK,
    });
    const payloadJSON = JSON.stringify({
        ...attributes,
        jti: encodeBase64urlNoPadding(bytes),
        htm: requestMethod,
        htu: requestURL.split("?")[0],
        iat: Math.floor(Date.now() / 1000),
        nonce: nonce ?? undefined,
    });
    const message = createJWTSignatureMessage(headerJSON, payloadJSON);
    const signature = await crypto.subtle.sign(
        {
            name: "ECDSA",
            hash: "SHA-256",
        },
        keyPair.privateKey,
        message
    );
    const dpop = encodeJWT(headerJSON, payloadJSON, new Uint8Array(signature));
    return dpop;
}

async function sendOAuthRequest(
    dpopKeyPair: CryptoKeyPair,
    request: Request,
    dpopNonce: string | null
): Promise<[response: Response, nonce: string | null]> {
    const clonedRequest = request.clone();
    let dpop = await createDPOP(
        dpopKeyPair,
        request.method,
        request.url,
        dpopNonce,
        {}
    );
    request.headers.set("DPoP", dpop);
    let response = await fetch(request, {
        signal: AbortSignal.timeout(5000),
    });
    let newDPOPNonce = response.headers.get("DPoP-Nonce");
    if (newDPOPNonce !== null) {
        dpopNonce = newDPOPNonce;
    }
    if (response.ok) {
        return [response, dpopNonce];
    }
    if (response.body == null) {
        throw new Error("Unexpected response");
    }

    // 32KB limit
    let resultBytes = await readAllStreamWithLimit(response.body, 1024 * 32);
    let result = JSON.parse(new TextDecoder().decode(resultBytes));
    let resultParser = new ObjectParser(result);
    let errorMessage = resultParser.getString("error");
    if (errorMessage !== "use_dpop_nonce") {
        if (clonedRequest.body !== null) {
            clonedRequest.body.cancel();
        }
        throw new Error(`OAuth error: ${errorMessage}`);
    }
    if (dpopNonce === null) {
        if (clonedRequest.body !== null) {
            clonedRequest.body.cancel();
        }
        throw new Error("Unexpected response");
    }
    dpop = await createDPOP(
        dpopKeyPair,
        request.method,
        request.url,
        dpopNonce,
        {}
    );
    clonedRequest.headers.set("DPoP", dpop);
    response = await fetch(clonedRequest, {
        signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
        if (response.body == null) {
            throw new Error("Unexpected response");
        }
        // 32KB limit
        resultBytes = await readAllStreamWithLimit(response.body, 1024 * 32);
        result = JSON.parse(new TextDecoder().decode(resultBytes));
        resultParser = new ObjectParser(result);
        errorMessage = resultParser.getString("error");
        throw new Error(`OAuth error: ${errorMessage}`);
    }
    return [response, dpopNonce];
}

export async function fetchProtectedResourceRequestWithDPOP(
    dpopKeyPair: CryptoKeyPair,
    issuer: string,
    accessToken: string,
    request: Request,
    dpopNonce: string | null
): Promise<[response: Response, nonce: string | null]> {
    request.headers.set("Authorization", `DPoP ${accessToken}`);
    const clonedRequest = request.clone();

    const accessTokenHashBytes = await sha256(
        new TextEncoder().encode(accessToken)
    );
    const accessTokenHash = encodeBase64urlNoPadding(accessTokenHashBytes);
    let dpop = await createDPOP(
        dpopKeyPair,
        request.method,
        request.url,
        dpopNonce,
        {
            iss: issuer,
            ath: accessTokenHash,
        }
    );
    request.headers.set("DPoP", dpop);
    let response = await fetch(request, {
        signal: AbortSignal.timeout(5000),
    });
    let newDPOPNonce = response.headers.get("DPoP-Nonce");
    if (newDPOPNonce !== null) {
        dpopNonce = newDPOPNonce;
    }
    if (response.status !== 401) {
        if (clonedRequest.body !== null) {
            clonedRequest.body.cancel();
        }
        return [response, dpopNonce];
    }
    let authenticate = response.headers.get("WWW-Authenticate");
    if (authenticate === null) {
        return [response, dpopNonce];
    }
    if (authenticate !== "DPoP" && !authenticate.startsWith("DPoP ")) {
        return [response, dpopNonce];
    }
    if (response.body !== null) {
        response.body.cancel();
    }

    dpop = await createDPOP(
        dpopKeyPair,
        request.method,
        request.url,
        dpopNonce,
        {
            iss: issuer,
            ath: accessTokenHash,
        }
    );
    clonedRequest.headers.set("DPoP", dpop);
    response = await fetch(clonedRequest, {
        signal: AbortSignal.timeout(5000),
    });
    newDPOPNonce = response.headers.get("DPoP-Nonce");
    if (newDPOPNonce !== null) {
        dpopNonce = newDPOPNonce;
    }
    return [response, dpopNonce];
}
