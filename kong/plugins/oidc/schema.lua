local typedefs = require "kong.db.schema.typedefs"

local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

function validate_headers(pair)
  local name, value = pair:match("^([^:]+):*(.-)$")
  if name == nil and value == nil then
    return nil, "Header format is not valid"
  end

  return true
end

local schema = {
  name = plugin_name,
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
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
            -- use only bearer token
            bearer_only = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            -- shown realm
            realm = {
              type = "string",
              required = true,
              default = "kong"
            }
          },
          {
            -- redirect uri to IdP
            redirect_uri = {
              type = "string",
              required = false
            }
          },
          {
            -- redirect path to IdP
            redirect_uri_path = {
              type = "string",
              required = false,
            }
          },
          {
            -- requested scopes
            scope = {
              type = "string",
              required = true,
              default = "openid"
            }
          },
          {
            -- response type from authorization request
            response_type = {
              type = "string",
              required = true,
              default = "code"
            }
          },
          {
            -- verify ssl from IdP
            ssl_verify = {
              type = "string",
              required = true,
              default = "no"
            }
          },
          {
            -- endpoint auth method to receive token from IdP
            token_endpoint_auth_method = {
              type = "string",
              required = true,
              default = "client_secret_basic"
            }
          },
          {
            -- kong used session secret
            session_secret = {
              type = "string",
              required = false
            }
          },
          {
            -- refresh session from authenticated user
            refresh_session_interval = {
              type = "number",
              required = false,
            }
          },
          {
            -- ?encryption?
            accept_none_alg = {
              type = "boolean",
              required = false,
              default = false
            }
          },
          {
            -- renew access token from user on expiry
            renew_access_token_on_expiry = {
              type = "boolean",
              required = true,
              default = true,
            }
          },
          {
            -- default expiry from access token when not set in response
            access_token_expires_in = {
              type = "number",
              default = 3600,
              required = true,
            }
          },
          {
            -- use nonce for authorization request
            use_nonce = {
              type = "boolean",
              default = true,
              required = true,
            }
          },
          {
            -- revoke tokens at logout at IdP
            revoke_tokens_on_logout = {
              type = "boolean",
              default = true,
              required = true,
            }
          },
          {
            -- when something went wrong
            recovery_page_path = {
              type = "string",
              required = false,
            }
          },
          {
            -- path for logut request
            logout_path = {
              type = "string",
              required = false,
              default = "/logout"
            }
          },
          {
            -- page to redirect after logout
            redirect_after_logout_uri = {
              type = "string",
              required = false,
              default = "/"
            }
          },
          {
            -- authorization param
            prompt = {
              type = "string",
              default = "consent",
              one_of = {
                "none",
                "login",
                "consent",
                "select_account",
              }
            },
          },
          {
            -- authorization param
            display = {
              type = "string",
              default = "page",
              one_of = {
                "page",
                "popup",
                "touch",
                "wap"
              }
            }
          },
          {
            -- authorization param
            max_age = {
              type = "number",
              required = false,
            }
          },
          {
            -- authorization param
            ui_locales = {
              type = "string",
              required = false,
            }
          },
          {
            -- authorization param
            id_token_hint = {
              type = "boolean",
              required = false,
              default = false,
            }
          },
          {
            -- authorization param
            acr_values = {
              type = "string",
              required = false,
            }
          },
          {
            -- session options for bungle/lua-resty-session
            session_options = {
              type = "record",
              fields = {
                {
                  cookie = {
                    type = "record",
                    fields = {
                      {
                        persistent = {
                          type = "string",
                          required = false,
                        }
                      },
                      {
                        domain = {
                          type = "string",
                          required = false,
                        }
                      },
                      {
                        path = {
                          type = "string",
                          required = false,
                        }
                      },
                      {
                        sameSite = {
                          type = "string",
                          required = false,
                        }
                      },
                      {
                        secure = {
                          type = "string",
                          required = false,
                        }
                      },
                      {
                        httpOnly = {
                          type = "string",
                          required = false,
                        }
                      }
                    }
                  }
                }
              }
            }
          },
          {
            -- when not to execute plugin
            filters = {
              type = "string"
            }
          },
          {
            disallowed_consumers = {
              type = "array",
              required = true,
              default = {},
              elements = { type = "string" }
            }
          },
        },
        entity_checks = {
          { at_least_one_of = { "redirect_uri", "redirect_uri_path" }, },
        },
      },
    },
  },
}

return schema
