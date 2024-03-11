package http.base.authz
import input
import data

allow {
  grp := input.claims["groups"]
  grp[_] == data.roles.permissions.user_groups[_]
  username := split(lower(input.claims.preferred_username),"@")[0]
  input.bucket == username
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}


allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == data.roles.permissions.user_groups[_]
  username := split(lower(input.claims.preferred_username),"@")[0]
  input.bucket == username
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# allow username/pwd auth for special cases
allow {
  username := input.account
  input.bucket == username
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# user anderlinil for bucket infn-ai-test
allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == data.roles.permissions.user_groups[_]
  username := split(lower(input.claims.preferred_username),"@")[0]
  username == "anderlinil"
  input.bucket == "infn-ai-test"
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}
