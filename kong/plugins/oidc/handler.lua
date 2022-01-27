--assert(ngx.get_phase() == "timer", "The world is coming to an end!")
---------------------------------------------------------------------------------------------
-- The handlers are based on the OpenResty handlers, see the OpenResty docs for details
-- on when exactly they are invoked and what limitations each handler has.
---------------------------------------------------------------------------------------------

-- imports
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local resolver = require("kong.plugins.oidc.resolver")
local resty_oidc = require("resty.openidc")

-- plugin configuration
-- set the plugin priority, which determines plugin execution order
local plugin = {
  PRIORITY = 1000,
  VERSION = "0.1",
}

-- do initialization here, any module level code runs in the 'init_by_lua_block',
-- before worker processes are forked. So anything you add here will run once,
-- but be available in all workers.

-- handles more initialization, but AFTER the worker process has been forked/created.
-- It runs in the 'init_worker_by_lua_block'
function plugin:init_worker()
  kong.log.debug("Init OidcHandler")
end

--[[ runs in the 'ssl_certificate_by_lua_block'
-- IMPORTANT: during the `certificate` phase neither `route`, `service`, nor `consumer`
-- will have been identified, hence this handler will only be executed if the plugin is
-- configured as a global plugin!
function plugin:certificate(plugin_conf)
  -- your custom code here
  kong.log.debug("saying hi from the 'certificate' handler")
end --]]


--[[ runs in the 'rewrite_by_lua_block'
-- IMPORTANT: during the `rewrite` phase neither `route`, `service`, nor `consumer`
-- will have been identified, hence this handler will only be executed if the plugin is
-- configured as a global plugin!
function plugin:rewrite(plugin_conf)
  -- your custom code here
  kong.log.debug("saying hi from the 'rewrite' handler")
end --]]


-- runs in the 'access_by_lua_block'
function plugin:access(plugin_conf)
  kong.log.inspect(plugin_conf)

  local oidc_config = utils.get_options(plugin_conf, ngx)

  if filter.shouldProcessRequest(oidc_config) then
    session.configure(oidc_config)
    handle(oidc_config, plugin_conf)
  else
    kong.log.debug("OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  kong.log.debug("OidcHandler done")
end

-- invoked inside access:handle
function handle(oidc_config, plugin_conf)
  local response
  if oidc_config.introspection_endpoint then
    kong.log.debug("Introspection endpoint configured, path: ".. oidc_config.introspection_endpoint)
    response = introspect(oidc_config)
    if response then
      kong.log.inspect(response)
      utils.injectUser(response)

      if plugin_conf.session_resolver.enabled then
        resolve_session(plugin_conf, response)
      end
    end
  end

  if response == nil then
    kong.log.debug("Make oidc request")
    response = make_oidc(oidc_config)
    if response then
      if(response.user) then
        kong.log.inspect("Inject user: ",response.user)
        utils.injectUser(response.user)
      end

      if(response.access_token) then
        kong.log.debug("Inject access_token: " .. response.access_token)
        utils.injectAccessToken(response.access_token)
      end

      if(response.id_token) then
        kong.log.inspect("Inject id_token: ", response.id_token)
        utils.injectIDToken(response.id_token)
      end

      if(response.user and plugin_conf.session_resolver.enabled) then
        kong.log.inspect("Resolve session for user: ", response.user)
        resolve_session(plugin_conf, response.user)
      end
    end
  end
end

-- resolve session with user from oidc
function resolve_session(plugin_conf, user)
  local session = nil
  local resolver_config, config_error = pcall(resolver.get_options(plugin_conf))

  if config_error then
    kong.log.error("Error while parsing config for session resolver: "..config_error)
  end

  if resolver_config then
    local response, request_error = pcall(resolver.resolve(resolver_config, user))
    if request_error then
      kong.log.err("Error while populating user session: "..request_error)
    end
    kong.log.inspect("Session response: ", response)
    session = response
  end

  local header = resolver_config.upstream_session_header
  utils.injectSession(session, header)
end

-- invoked inside handle
function make_oidc(oidc_config)
  kong.log.debug("OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = resty_oidc.authenticate(oidc_config)
  if err then
    kong.log.error("OidcHandler error: " ..err)
    if oidc_config.recovery_page_path then
      kong.log.debug("Recovery page configured, path: " .. oidc_config.recovery_page_path)
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

-- runs in the 'header_filter_by_lua_block'
-- function plugin:header_filter(plugin_conf)
  -- your custom code here, for example;
--  kong.response.set_header(plugin_conf.response_header, "this is on the response")
--end --]]

--[[ runs in the 'body_filter_by_lua_block'
function plugin:body_filter(plugin_conf)
  -- your custom code here
  kong.log.debug("saying hi from the 'body_filter' handler")
end --]]

--[[ runs in the 'log_by_lua_block'
function plugin:log(plugin_conf)
  -- your custom code here
  kong.log.debug("saying hi from the 'log' handler")
end --]]

-- return plugin
return plugin
