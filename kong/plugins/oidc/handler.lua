--assert(ngx.get_phase() == "timer", "The world is coming to an end!")
---------------------------------------------------------------------------------------------
-- The handlers are based on the OpenResty handlers, see the OpenResty docs for details
-- on when exactly they are invoked and what limitations each handler has.
---------------------------------------------------------------------------------------------

-- imports
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
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

  local oidcConfig = utils.get_options(plugin_conf, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(plugin_conf)
    handle(plugin_conf)
  else
    kong.log.debug("OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  kong.log.debug("OidcHandler done")
end

-- invoked inside access:handle
function handle(plugin_conf)
  local response
  if plugin_conf.introspection_endpoint then
    kong.log.debug("Introspection endpoint configured, path: ".. plugin_conf.introspection_endpoint)
    response = introspect(plugin_conf)
    if response then
      kong.log.inspect(response)
      utils.injectUser(response)
    end
  end

  if response == nil then
    kong.log.debug("Make oidc request")
    response = make_oidc(plugin_conf)
    if response then
      if(response.user) then
        kong.log.debug("Inject user: " .. response.user)
        utils.injectUser(response.user)
      end

      if(response.access_token) then
        kong.log.debug("Inject access_token: " .. response.access_token)
        utils.injectAccessToken(response.access_token)
      end

      if(response.id_token) then
        kong.log.debug("Inject id_token: " .. response.id_token)
        utils.injectIDToken(response.id_token)
      end
    end
  end
end

-- invoked inside handle
function make_oidc(plugin_conf)
  kong.log.debug("OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = pcall(resty_oidc.authenticate(plugin_conf))
  if err then
    kong.log.debug("OidcHandler error: " .. err)
    if oidcConfig.recovery_page_path then
      kong.log.debug("Recovery page configured, path: " .. plugin_conf.recovery_page_path)
      ngx.redirect(plugin_conf.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

-- invoked inside handle
function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local res, err = pcall(resty_oidc.introspect(oidcConfig))
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
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
