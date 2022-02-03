local utils = require("kong.plugins.oidc.utils")

local M = {}

-- configure session secret
function M.configure(config)
  if config.session_secret then
    local decoded_session_secret = ngx.decode_base64(config.session_secret)
    if not decoded_session_secret then
      kong.log.debug("Can't decode session secret")
      utils.exit(500, "invalid OIDC plugin configuration, session secret could not be decoded", ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR))
    end
    kong.log.debug("Decoded session secret: ", decoded_session_secret)
    ngx.var.session_secret = decoded_session_secret
  end
end

return M
