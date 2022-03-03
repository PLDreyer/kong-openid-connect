local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local resty_oidc = require("resty.openidc")
local resty_session = require("resty.session")

local plugin = {
  -- last authentication priority
  -- if no resolved user found, redirect to IdP
  PRIORITY = 995,
  VERSION = "0.1",
}

-- runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)
  local oidc_config = utils.get_options(plugin_conf, ngx)

  if filter.shouldProcessRequest(oidc_config) then
    kong.log.debug("Filter match to process oidc")

    local consumer = utils.get_current_consumer()
    utils.debug_log_table("Consumer before oidc: ", consumer)
    if not consumer or consumer and utils.is_disallowed_consumer(oidc_config, consumer) then
      kong.log.debug("Either no consumer or disallowed consumer found. Proceeding")
      handle(oidc_config, plugin_conf)
    else
      kong.log.debug("Resolved header found. Ignore processing")
    end

  else
      kong.log.debug("OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  kong.log.debug("OidcHandler done")
end

-- invoked inside access:handle
function handle(oidc_config, plugin_conf)
  local response

  if oidc_config.introspection_endpoint then
    kong.log.debug("Introspection endpoint configured, path: ", oidc_config.introspection_endpoint)
    response = introspect(oidc_config)

    if response then
      utils.debug_log_table("Introsection response: ", response)
      utils.injectUser(response)
    end
  end

  if response == nil then
    kong.log.debug("Make oidc request")
    response = make_oidc(oidc_config)
    if response then
      kong.log.inspect("IdP Response: ", response)
      if(response.user) then
        utils.debug_log_table("Inject user: ", response.user)
        utils.injectUser(response.user)
      end

      if(response.access_token) then
        utils.debug_log_table("Inject access token: ", response.access_token)
        utils.injectAccessToken(response.access_token)
      end

      if(response.id_token) then
        utils.debug_log_table("Inject id token: ", response.id_token)
        utils.injectIDToken(response.id_token)
      end
    end
  end
end

-- invoked inside handle
function make_oidc(oidc_config)
  kong.log.debug("Calling authenticate, requested path: ", ngx.var.request_uri)
  local requested_location = nil

  local session, present, reason = resty_session.open()
  if not present then
    kong.log.debug("Session not present. Reason: ", reason)
    requested_location = kong.request.get_scheme() .. "://" .. kong.request.get_host() .. kong.request.get_path()
    kong.log.debug("Request path generated: ", requested_location)
  end

  session:close()

  local res, err, var1, var2 = resty_oidc.authenticate(oidc_config, requested_location, nil, oidc_config.session_options)

  kong.log.inspect("RES: ", res)
  kong.log.inspect("ERR: ", err)
  kong.log.inspect("VAR1: ", var1)
  kong.log.inspect("VAR2: ", var2)

  if err then
    kong.log.err("var1: ", var1)
    kong.log.err("var2: ", var2)
    kong.log.err("OidcHandler error: ", err)

    if oidc_config.recovery_page_path then
      kong.log.debug("Recovery page configured, path: ", oidc_config.recovery_page_path)
      ngx.redirect(oidc_config.recovery_page_path)
    end

    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  return res
end

-- invoked inside handle
function introspect(oidc_config)
  if utils.has_bearer_access_token() or oidc_config.bearer_only == "yes" then
    local res, err = pcall(resty_oidc.introspect(oidc_config))

    if err then
      if oidc_config.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidc_config.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end

      return nil
    end

    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end

  return nil
end

return plugin
