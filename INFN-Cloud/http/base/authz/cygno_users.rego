package http.base.authz
import input
import data

allow {
  input.account == "cygnodm"
  input.bucket == data.roles.permissions.cygno_buckets[_]
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Allow users of group Cygno-admis to manage their own data.
allow {
  grp := input.claims.groups
  grp[_] == "cygno"
  input.bucket == data.roles.permissions.cygno_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Same for wlcg profile
allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == "/cygno"
  input.bucket == data.roles.permissions.cygno_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Allow users of group Cygno to see the data.
allow {
  grp := input.claims.groups
  grp[_] == "cygno-users"
  input.bucket == data.roles.permissions.cygno_data_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.scratch
  permissions[_] == {"action": input.action}
}

# Wlcg profile
allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == "/cygno-users"
  input.bucket == data.roles.permissions.cygno_data_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.scratch
  permissions[_] == {"action": input.action}
}

# Allow users of group Cygno to manage their analysis and simulations.
allow {
  grp := input.claims.groups
  grp[_] == "cygno-users"
  input.bucket == data.roles.permissions.cygno_work_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Wlcg profile
allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == "/cygno-users"
  input.bucket == data.roles.permissions.cygno_work_buckets[_]
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}
