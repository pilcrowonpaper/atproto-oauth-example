# AT Protocol OAuth example

An example implementation of an AT Protocol (BlueSky) OAuth client using Astro. This example does not use the AT Protocol SDK. It also doesn't use any Node-specific APIs (except for `process.env`) and should run in other runtimes (including Cloudflare Workers).

Not tested, but it should work PDS and authorization servers not hosted by BlueSky.

## Initialize locally

Install dependencies and start the server at port 4321. If you'd like to use a different port, change all occurrences of port 4321 in the codebase.

```
pnpm i
pnpm dev
```

## Deploying to production

This example uses confidential OAuth clients when deployed.

The AT Protocol requires confidential clients to use signed JWTs for authentication and this example uses JWTs signed with ECDSA with the P-256 curve. Generate a private and public key with `openssl`:

```
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve | openssl pkcs8 -topk8 -nocrypt -outform pem > oauth-private-key.pem

openssl ec -in oauth-private-key.pem -pubout > oauth-public-key.pem
```

This should generate 2 files: `oauth-private-key.pem` and `oauth-public-key.pem`.

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM5BHQhVKR9STxiJG
IE+Jb/yxQvftew9HknEQUGaRsSqhRANCAAQH3r8GHE27Gsy0sHQRUSo9yqu8r58F
nBuWEIaxldS8he/3ZVHUim7qXe9knTa1O2aHsIVTnC8FiZ6J0tvJecE8
-----END PRIVATE KEY-----
```

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB96/BhxNuxrMtLB0EVEqPcqrvK+f
BZwblhCGsZXUvIXv92VR1Ipu6l3vZJ02tTtmh7CFU5wvBYmeidLbyXnBPA==
-----END PUBLIC KEY-----
```

Remove the header and footer from the `.pem` files and set the base64 encoded string as `OAUTH_PRIVATE_KEY` for the private key and as `OAUTH_PUBLIC_KEY` for the public key.

```bash
OAUTH_PRIVATE_KEY="MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM5BHQhVKR9STxiJGIE+Jb/yxQvftew9HknEQUGaRsSqhRANCAAQH3r8GHE27Gsy0sHQRUSo9yqu8r58FnBuWEIaxldS8he/3ZVHUim7qXe9knTa1O2aHsIVTnC8FiZ6J0tvJecE8"
OAUTH_PUBLIC_KEY="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB96/BhxNuxrMtLB0EVEqPcqrvK+fBZwblhCGsZXUvIXv92VR1Ipu6l3vZJ02tTtmh7CFU5wvBYmeidLbyXnBPA=="
```

Also set a `OAUTH_KEY_PAIR_ID` environment variable. This will be the public ID of your key pair and does not need to be unguessable.

```bash
OAUTH_KEY_PAIR_ID="banana"
```

Finally, set your site's public URL (make sure to include `https://`):

```bash
PUBLIC_URL="https://example.com"
```
