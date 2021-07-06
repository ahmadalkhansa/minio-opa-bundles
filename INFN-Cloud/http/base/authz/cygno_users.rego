package http.base.authz
import input
import data

# Allow users of group Cygno-admis to manage their own data.
allow {
  grp := input.claims.groups
  grp[_] == "cygno"
  input.bucket == "cygnus"
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Same for wlcg profile
allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == "/cygno"
  input.bucket == "cygnus"
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Allow users of group Cygno to see their own data.
allow {
  grp := input.claims.groups
  grp[_] == "cygno-users"
  input.bucket == "cygnus"
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.scratch
  permissions[_] == {"action": input.action}
}

# Wlcg profile
allow {
  grp := input.claims["wlcg.groups"]
  grp[_] == "/cygno-users"
  input.bucket == "cygnus"
  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.scratch
  permissions[_] == {"action": input.action}
}
