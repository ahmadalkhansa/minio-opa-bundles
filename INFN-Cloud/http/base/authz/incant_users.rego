package http.base.authz
import input
import data

# Allow users of group incant to manage their own data.
allow {
  grp := input.claims.groups
  grp[_] == data.roles.permissions.incant_users_groups[_]
  input.bucket == data.roles.permissions.incant_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Same for wlcg profile
allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == data.roles.permissions.incant_users_groups[_]
  input.bucket == data.roles.permissions.incant_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}
