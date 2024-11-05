import { DynamicBuffer } from "@oslojs/binary";

export function joinURIBaseAndPath(base: string, ...parts: string[]): string {
    let joined = trimRight(base, "/");
    for (const part of parts) {
        joined += "/";
        joined += trimRight(trimLeft(part, "/"), "/");
    }
    return joined;
}

export function trimLeft(s: string, cutset: string): string {
    while (s.length >= cutset.length && s.slice(0, cutset.length) === cutset) {
        s = s.slice(cutset.length);
    }
    return s;
}

export function trimRight(s: string, cutset: string): string {
    while (
        s.length >= cutset.length &&
        s.slice(cutset.length * -1) === cutset
    ) {
        s = s.slice(0, cutset.length * -1);
    }
    return s;
}

export async function readAllStreamWithLimit(
    stream: ReadableStream<Uint8Array>,
    limitInBytes: number
): Promise<Uint8Array> {
    let readBytes = 0;
    const buffer = new DynamicBuffer(0);
    const reader = stream.getReader();
    while (true) {
        const { done, value } = await reader.read();
        if (done) {
            break;
        }
        readBytes += value.byteLength;
        if (readBytes > limitInBytes) {
            await reader.cancel();
            throw new Error("Limit reached");
        }
        buffer.write(value);
    }
    return buffer.bytes();
}

export async function createECDSAPublicKeyJWK(
    publicKey: CryptoKey
): Promise<object> {
    const webcryptoJWK = await crypto.subtle.exportKey("jwk", publicKey);
    const jwk = {
        kty: webcryptoJWK.kty,
        crv: webcryptoJWK.crv,
        x: webcryptoJWK.x,
        y: webcryptoJWK.y,
        use: "sig",
    };
    return jwk;
}

export async function createECDSAPublicKeyJWKWithId(
    publicKey: CryptoKey,
    id: string
): Promise<object> {
    const webcryptoJWK = await crypto.subtle.exportKey("jwk", publicKey);
    const jwk = {
        kid: id,
        kty: webcryptoJWK.kty,
        crv: webcryptoJWK.crv,
        x: webcryptoJWK.x,
        y: webcryptoJWK.y,
        use: "sig",
    };
    return jwk;
}
