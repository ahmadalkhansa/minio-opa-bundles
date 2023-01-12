package http.base.authz
import input
import data

allow {
  grp := input.claims.groups
  grp[_] == data.roles.permissions.user_groups[_]
  username := replace(split(lower(input.claims.preferred_username),"@")[0], "_", "")
  input.bucket == username
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Map sub to username
allow {

  input.claims.aud == "https://wlcg.cern.ch/jwt/v1/any"

  sub := input.claims.sub
  input.bucket == replace(split(lower(data.roles.usermap[sub]),"@")[0], "_", "")
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Temp hack for HERD GROUP
allow {
  username := replace(split(lower(input.claims.preferred_username),"@")[0], "_", "")
  username == "mori"
  input.bucket == "duranti"
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

allow {
  username := input.account
  input.bucket == username
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}
