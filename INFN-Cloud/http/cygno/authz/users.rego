package http.cygno.authz
import input
import data

# Allow users of group Cygno to manage their own data.
allow {
  grp := input.claims.groups
  grp[_] == "Cygno"
  input.bucket == "cygnus"
  input.claims.iss == data.roles.permissions.issuer
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}