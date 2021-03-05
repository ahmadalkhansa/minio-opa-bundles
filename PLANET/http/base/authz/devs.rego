package http.base.authz
import input
import data

# Allow to retrieve and see data from other users in scratch area
allow {
  input.bucket == "scratch"
  grp := input.claims.groups
  grp[_] == "devs"
  input.claims.iss == data.roles.permissions.issuer
  permissions := data.roles.permissions.user
  # check if the permission granted to r matches the user's request
  permissions[_] == {"action": input.action}
}