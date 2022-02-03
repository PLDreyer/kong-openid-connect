local cjson = require("cjson")
local errlog = require("ngx.errlog")
local constants = require "kong.constants"

local kong = kong
local ngx_DEBUG = ngx.DEBUG
local M = {}

-- generate ignore routes from filters
local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

-- generate redirect uri path
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

-- generate oidc config
function M.get_options(config, ngx)
  local options = {
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
    disallowed_consumers = config.disallowed_consumers,
    filters = parseFilters(config.filters),
  }
  M.debug_log_table("Plugin config for oidc: ", options)
  return options
end

-- set consumer and credential with header
local function set_consumer(consumer, credential)
  kong.client.authenticate(consumer, credential)

  local set_header = kong.service.request.set_header
  local clear_header = kong.service.request.clear_header

  if consumer and consumer.id then
    set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  else
    clear_header(constants.HEADERS.CONSUMER_ID)
  end

  if consumer and consumer.custom_id then
    set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  else
    clear_header(constants.HEADERS.CONSUMER_CUSTOM_ID)
  end

  if consumer and consumer.username then
    set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  else
    clear_header(constants.HEADERS.CONSUMER_USERNAME)
  end

  if credential and credential.key then
    set_header(constants.HEADERS.CREDENTIAL_IDENTIFIER, credential.key)
  else
    clear_header(constants.HEADERS.CREDENTIAL_IDENTIFIER)
  end

  clear_header(constants.HEADERS.CREDENTIAL_USERNAME)

  if credential then
    clear_header(constants.HEADERS.ANONYMOUS)
  else
    set_header(constants.HEADERS.ANONYMOUS, true)
  end
end

-- wrapper function to nicely cancel request
function M.exit(http_status_code, message, ngx_code)
  kong.log.debug("Send exit: ", http_status_code, message, ngx_code)
  ngx.status = http_status_code
  ngx.say(message)
  ngx.exit(ngx_code)
end

-- inject access token for upstream service
function M.injectAccessToken(access_token)
  kong.log.debug("Injecting access token in header: ", access_token)
  kong.service.request.set_header("X-Access-Token", access_token)
end

-- inject id token for upstream service
function M.injectIDToken(id_token)
  M.debug_log_table("Injecting id token base64 encoded in header: ", id_token)
  local token_str = cjson.encode(id_token)
  kong.service.request.set_header("X-ID-TOKEN", ngx.encode_base64(token_str))
end

-- inject user for upstream service
function M.injectUser(user)
  local consumer = {}
  consumer.id = "null"
  consumer.username = user.email
  consumer.custom_id = user.sub

  M.debug_log_table("Injecting oauth userinfo base64 encoded in header: ", user)
  M.debug_log_table("Injecting modified consumer: ", consumer)
  -- authenticate with tmp_user as consumer and credential
  set_consumer(consumer, consumer)

  local userinfo = cjson.encode(user)
  kong.service.request.set_header("X-Userinfo", ngx.encode_base64(userinfo))
end

-- check request for bearer access token
function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header and header:find(" ") then
    local divider = header:find(' ')
    if string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      kong.log.debug("Request has bearer access token")
      return true
    end
  end
  kong.log.debug("Request hasn't bearer access token")
  return false
end

-- check if disallowed consumer is defined
function M.is_disallowed_consumer(oidc_config, consumer)
  local tmp_consumer = consumer
  local disallowed_consumers = oidc_config.disallowed_consumers
  if table.getn(disallowed_consumers) == 0 then
    kong.log.debug("No disallowed consumers defined. Proceeding")
    return false
  end

  if not consumer then
    tmp_consumer = kong.client.get_consumer()
    if not tmp_consumer then
      kong.log.debug("No authenticated consumer found.")
      return false
    end
  end

  for _, disallowed_consumer in ipairs(disallowed_consumers) do
    if tmp_consumer.id == disallowed_consumer or tmp_consumer.username == disallowed_consumer then
      kong.log.debug("Disallowed consumer found.")
      return true
    end
  end

  kong.log.debug("No disallowed consumer found.")
  return false
end

-- receive current authenticated consumer
function M.get_current_consumer()
  local consumer = kong.client.get_consumer()
  return consumer
end

-- wrapper function to inspect tables in debug mode
function M.debug_log_table(...)
  local log_level = errlog.get_sys_filter_level()
  if log_level == ngx_DEBUG then
    kong.log.inspect(...)
  end
end

return M
