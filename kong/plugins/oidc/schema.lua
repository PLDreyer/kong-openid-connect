local typedefs = require "kong.db.schema.typedefs"

-- Grab pluginname from module name
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

local schema = {
  name = plugin_name,
  fields = {
    -- the 'fields' array is the top-level entry with fields defined by Kong
    { consumer = typedefs.no_consumer },  -- this plugin cannot be configured on a consumer (typical for auth plugins)
    { protocols = typedefs.protocols_http },
    { config = {
        -- The 'config' record is the custom part of the plugin schema
        type = "record",
        fields = {
          -- a standard defined field (typedef), with some customizations
          --{ request_header = typedefs.header_name {
          --    required = true,
          --    default = "Hello-World" } },
          --{ response_header = typedefs.header_name {
          --    required = true,
          --    default = "Bye-World" } },
          --{ ttl = { -- self defined field
          --    type = "integer",
          --    default = 600,
          --    required = true,
          --    gt = 0, }}, -- adding a constraint for the value
          {
            -- client_id of registered client
            client_id = {
              required = true,
              type = "string"
            },
          },
          {
            -- client_secret of registered client
            client_secret = {
              required = true,
              type = "string",
            }
          },
          {
            -- discovery endpoint of authorization server
            discovery = {
              required = true,
              type = "string"
            }
          },
          {
            -- token introspection endpoint of authorization server
            introspection_endpoint = {
              required = false,
              type = "string"
            }
          },
          {
            -- timeout for connect/send/read
            timeout = {
              type = "number",
              required = false,
            }
          },
          {
            -- introspection endpoint auth method configured for client
            introspection_endpoint_auth_method = {
              type = "string",
              required = true,
            }
          },
          {

            bearer_only = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            realm = {
              type = "string",
              required = true,
              default = "kong"
            }
          },
          {
            redirect_uri = {
              type = "string",
              required = false
            }
          },
          {
            redirect_uri_path = {
              type = "string",
              required = false,
            }
          },
          {
            scope = {
              type = "string",
              required = true,
              default = "openid"
            }
          },
          {
            response_type = {
              type = "string",
              required = true,
              default = "code"
            }
          },
          {
            ssl_verify = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            token_endpoint_auth_method = {
              type = "string",
              required = true,
              default = "client_secret_basic"
            }
          },
          {
            session_secret = {
              type = "string",
              required = false
            }
          },
          {
            refresh_session_interval = {
              type = "number",
              required = false,
            }
          },
          {
            accept_none_alg = {
              type = "boolean",
              required = false,
              default = false
            }
          },
          {
            renew_access_token_on_expiry = {
              type = "boolean",
              required = true,
              default = true,
            }
          },
          {
            access_token_expires_in = {
              type = "number",
              default = 3600,
              required = true,
            }
          },
          {
            use_nonce = {
              type = "boolean",
              default = true,
              required = true,
            }
          },
          {
            revoke_tokens_on_logout = {
              type = "boolean",
              default = true,
              required = true,
            }
          },
          {
            recovery_page_path = {
              type = "string",
              required = false,
            }
          },
          {
            logout_path = {
              type = "string",
              required = false,
              default = "/logout"
            }
          },
          {
            redirect_after_logout_uri = {
              type = "string",
              required = false,
              default = "/"
            }
          },
          {
            session_resolver = {
              type = "record",
              fields = {
                {
                  enabled = {
                    type = "boolean",
                    default = false,
                  },
                },
                {
                  endpoint = {
                    type = "string",
                    required = false,
                  },
                },
                {
                  userinfo_property = {
                    type = "string",
                    required = false,
                    default = "sub"
                  },
                },
                {
                  upstream_session_header = {
                    type = "string",
                    required = false,
                  },
                }
              }
            }
          },
          {
            filters = {
              type = "string"
            }
          }
        },
        entity_checks = {
          -- add some validation rules across fields
          -- the following is silly because it is always true, since they are both required
          { at_least_one_of = { "redirect_uri", "redirect_uri_path" }, },
          -- We specify that both header-names cannot be the same
          -- { distinct = { "request_header", "response_header"} },
        },
      },
    },
  },
}

return schema
