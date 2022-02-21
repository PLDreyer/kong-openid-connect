local plugin_name = "oidc"
local package_name = "kong-plugin-" .. plugin_name
local package_version = "0.1.0"
local rockspec_revision = "1"

package = package_name
version = package_version .. "-" .. rockspec_revision
supported_platforms = { "linux", "macosx" }
source = {
  url = "git://github.com.git",
  branch = "master"
}

description = {
  summary = "Kong is a scalable and customizable API Management Layer built on top of Nginx.",
  license = "Apache 2.0",
}

dependencies = {
    "lua >= 5.1",
    "lua-resty-openidc ~> 1.7.5-1",
    "lua-resty-session >= 2.8",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..plugin_name..".handler"] = "kong/plugins/"..plugin_name.."/handler.lua",
    ["kong.plugins."..plugin_name..".schema"] = "kong/plugins/"..plugin_name.."/schema.lua",
    ["kong.plugins."..plugin_name..".filter"] = "kong/plugins/"..plugin_name.."/filter.lua",
    ["kong.plugins."..plugin_name..".utils"] = "kong/plugins/"..plugin_name.."/utils.lua",
    ["kong.plugins."..plugin_name..".session"] = "kong/plugins/"..plugin_name.."/session.lua",
  }
}
