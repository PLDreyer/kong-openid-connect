Kong oidc connect
====================

This repository is based on the great work of kong-plugin-template, lua-resty-openidc and kong-oidc

Designed to used with pongo or vagrant.

Dependencies
============
- lua-resty-openidc ~> 1.7.5-1

Configuration
=============
```lua
local config = {
    -- oauth client id
    client_id = "client_id",
    -- oauth client secret
    client_secret = "client_secret",
    -- oauth discovery endpoint
    discovery = "https://example.com/.well-known/openid-configuration",
    -- oauth token introspection endpoint
    introspection_endpoint = "https://example.com/auth/token",
    -- timeout
    timeout = 2000,
    -- oauth introspection endpoint auth method: 'client_secret_basic', 'client_secret_post'...
    introspection_endpoint_auth_method = "client_secret_post",
    -- use bearer only
    bearer_only = "no",
    -- realm to show
    realm = "kong",
    -- redirect uri for authorization code flow
    redirect_uri = "https://example.com/auth/cb",
    -- scopes to request
    scopes = "openid email profile",
    -- response type to use
    response_type = "code",
    -- verify ssl
    ssl_verify = "yes",
    -- token endpoint auth method
    token_endpoint_auth_method = "client_secret_post",
    -- session secret from kong to use
    session_secret = "very_secure",
    -- interval to refresh token information
    refresh_session_interval = 36000,
    -- accept none alg
    accept_none_alg = false,
    -- renew access token on expiry
    renew_access_token_on_expiry = true,
    -- default expiry from access token when not set in response
    access_token_expires_in = 3600,
    -- use a nonce for flow
    use_nonce = true,
    -- revoke tokens on logout
    revoke_tokens_on_logout = true,
    -- recovery page path when something fails
    recovery_page_path = "https://example.com/error",
    -- logout path for request
    logout_path = "https://example.com/logout",
    -- redirect to uri after logout
    redirect_after_logout_uri = "https://example.com",
    -- authorization param
    prompt = "consent",
    -- authorization param
    display = "page",
    -- authorization param
    max_age = 36000,
    -- authorization param
    ui_locales = "de-DE",
    -- authorization param
    id_token_hint = true,
    -- authorization param
    acr_values = "0",
    -- session options
    -- only options set will be passed
    session_options = {
        cookie = {
            persistent = "off",
            domain = "example.com",
            path = "/",
            sameSite = "Lax",
            secure = "on",
            httpOnly = "on",
        },
    },
    -- filters for domains
    filters = "max.com, mustermann.com",
    -- disallowed consumers have to be processed
    disallowed_consumers = {
        "not-allowed-anonymous-user"
    }
}
```
For further information on configuration consult documentation from lua-resty-openidc

Implementation
==============



### Scripts

- pongo run -- run specs

- pongo shell -- test plugin
