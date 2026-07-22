wendigo
---

A simple token exchange service designed to take and validate JWTs, and return new JWTs signed by its key. Useful for federating identities from multiple providers under a single provider for third parties that only accept a single one. Great for small companies without the resources to buy/manage a full fledged central identity provider.

For example, if you're running multiple EKS clusters and relying on the internal OIDC provider but an upstream provider will only accept one.

Named after the Native American Wendigo because rolling your own auth can be spooky.

# Running

Take the provided `config.yml.example` and rename it to `config.yml`, updating config values for your needs.

Run the service, it is intended to be behind a loadbalancer that terminates TLS.

# Usage

Send a POST request to the `/token` endpoint with a `Authorization` header in `bearer <token>` format. The response is a JSON blob with the `access_token`, `token_type`, and `expires_in` fields.

There's also a GET endpoint at `/.well-known/jwks.json` to return the JWKS file for validation.
