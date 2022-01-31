local cjson = require("cjson")

local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

function M.get_redirect_uri_path(ngx)
  local function drop_query()
    local uri = ngx.var.request_uri
    local x = uri:find("?")
    if x then
      return uri:sub(1, x - 1)
    else
      return uri
    end
  end

  local function tackle_slash(path)
    local args = ngx.req.get_uri_args()
    if args and args.code then
      return path
    elseif path == "/" then
      return "/cb"
    elseif path:sub(-1) == "/" then
      return path:sub(1, -2)
    else
      return path .. "/"
    end
  end

  return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    introspection_endpoint = config.introspection_endpoint,
    timeout = config.timeout,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    bearer_only = config.bearer_only,
    realm = config.realm,
    redirect_uri_path = config.redirect_uri_path,
    redirect_uri = config.redirect_uri,
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    refresh_session_interval = config.refresh_session_interval,
    accept_none_alg = config.accept_none_alg,
    renew_access_token_on_expiry = config.renew_access_token_on_expiry,
    access_token_expires_in = config.access_token_expires_in,
    use_nonce = config.use_nonce,
    revoke_tokens_on_logout = config.revoke_tokens_on_logout,
    recovery_page_path = config.recovery_page_path,
    logout_path = config.logout_path,
    redirect_after_logout_uri = config.redirect_after_logout_uri,
    filters = parseFilters(config.filters),
  }
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectAccessToken(accessToken)
  ngx.req.set_header("X-Access-Token", accessToken)
end

function M.injectIDToken(idToken)
  local tokenStr = cjson.encode(idToken)
  ngx.req.set_header("X-ID-Token", ngx.encode_base64(tokenStr))
end

function M.injectUser(user)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  -- saves user in shared plugin context
  kong.ctx.shared.authenticated_credential = tmp_user

  -- saves user in kong context. most used for session
  ngx.ctx.authenticated_credential = tmp_user
  local userinfo = cjson.encode(user)
  ngx.req.set_header("X-Userinfo", ngx.encode_base64(userinfo))
end

function M.injectSession(session, header)
  local encoded_session = cjson.encode(session)
  ngx.req.set_header(header, encoded_session)
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

return M
