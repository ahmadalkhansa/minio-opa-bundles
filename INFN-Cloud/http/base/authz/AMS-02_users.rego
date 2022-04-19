package http.base.authz
import input
import data

# Allow users of group users/AMS-02 to manage their own data.
allow {
  grp := input.claims.groups
  grp[_] == "users/AMS-02"
  input.bucket == data.roles.permissions.AMS_02_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}
