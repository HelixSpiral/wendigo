wendigo
---

A simple token exchange service designed to take and validate JWTs, and return new JWTs signed by its key. Useful for federating identities from multiple providers under a single provider for third parties that only accept a single one. Great for small companies without the resources to buy/manage a full fledged central identity provider.

For example, if you're running multiple EKS clusters and relying on the internal OIDC provider but an upstream provider will only accept one.

Named after the Native American Wendigo because rolling your own auth can be spooky.
