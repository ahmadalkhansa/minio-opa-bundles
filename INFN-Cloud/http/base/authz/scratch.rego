package http.base.authz
import input
import data

# Allow to retrieve and see data from other users in scratch area
allow {
  input.bucket == "scratch"
  permissions := data.roles.permissions.scratch
  # check if the permission granted to r matches the user's request
  permissions[_] == {"action": input.action}
  startswith(input.claims.iss, data.roles.permissions.issuer)
}

# Allow users to write on scratch/<username> folder
allow {
  username := split(lower(input.claims.preferred_username),"@")[0]

  ref := input.conditions.Referer[_]

  url := concat("/", ["^https://.*/minio/scratch",username,".*$"] )

  re_match( url , ref)

  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Allow users to write on scratch/<username> folder
allow {
  username := input.account

  ref := input.conditions.Referer[_]

  url := concat("/", ["^https://.*/minio/scratch",username,".*$"] )

  re_match( url , ref)

  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}
