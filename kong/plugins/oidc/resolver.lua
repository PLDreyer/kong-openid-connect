local http = require('resty.http')

local M = {}

function M.get_options(plugin_conf)
  local rs = plugin_conf.session_resolver

  if not rs.enabled then
    return
  end

  return {
    endpoint = rs.endpoint,
    userinfo_property = rs.userinfo_property,
    upstream_session_header = rs.upstream_session_header
  }
end

function M.resolve(resolver_config, user)
  local endpoint = resolver_config.endpoint
  local userinfo_property = resolver_config.userinfo_property

  local httpc = http.new()
  configure_http_request(httpc)

  local response, request_err = httpc:request_uri(endpoint, {
    path = "/"..user[userinfo_property]
  })

  if request_err then
    error(request_err)
  end

  return response
end

function configure_http_request(httpc)
  httpc:set_timeout(3000)
end

return M
