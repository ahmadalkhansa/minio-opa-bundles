package http.base.authz
import input
import data

# Allow to retrieve and see data from other users in data area
allow {
  input.bucket == "data"
  permissions := data.roles.permissions.scratch
  # check if the permission granted to r matches the user's request
  permissions[_] == {"action": input.action}
  startswith(input.claims.iss, data.roles.permissions.issuer)
}