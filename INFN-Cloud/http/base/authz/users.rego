package http.base.authz
import input
import data

allow {
  grp := input.claims.groups
  grp[_] == "end-users-catchall"
  username := split(lower(input.claims.preferred_username),"@")[0]
  input.bucket == username
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

allow {
  grp := input.claims.groups
  grp[_] == "end-users-catchall"
  username := input.account
  input.bucket == username
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}
