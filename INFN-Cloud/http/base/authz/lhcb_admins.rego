package http.base.authz
import input
import data

allow {
  grp := input.claims.groups
  grp[_] == data.roles.permissions.lhcb_admin_groups[_]
  input.bucket == "lhcb-data"
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Allow to retrieve and see data from other users in scratch area (wlcg profile)
allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == data.roles.permissions.lhcb_admin_groups[_]

  input.claims.aud == "https://wlcg.cern.ch/jwt/v1/any"

  input.bucket == "lhcb-data"
  permissions := data.roles.permissions.user
  # check if the permission granted to r matches the user's request
  permissions[_] == {"action": input.action}
  #startswith(input.claims.iss, data.roles.permissions.issuer)
}