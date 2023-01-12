package http.base.authz
import input
import data

# Allow to retrieve and see data from other users in scratch area
allow {
  grp := input.claims.groups
  grp[_] == data.roles.permissions.user_groups[_]
  input.bucket == "scratch"
  permissions := data.roles.permissions.scratch
  # check if the permission granted to r matches the user's request
  permissions[_] == {"action": input.action}
  #startswith(input.claims.iss, data.roles.permissions.issuer)
}

# Allow to retrieve and see data from other users in scratch area (wlcg profile)
allow {
  input.claims.aud == "https://wlcg.cern.ch/jwt/v1/any"

  input.bucket == "scratch"
  permissions := data.roles.permissions.scratch
  # check if the permission granted to r matches the user's request
  permissions[_] == {"action": input.action}
  #startswith(input.claims.iss, data.roles.permissions.issuer)
}

#### Referer included in s3 request

# Allow users to write on scratch/<username> folder
allow {
  grp := input.claims.groups
  grp[_] == data.roles.permissions.user_groups[_]

  username := replace(split(lower(input.claims.preferred_username),"@")[0], "_", "")
  
  ref := input.conditions.Referer[_]

  url := concat("/", ["^https://.*/minio/scratch",username,".*$"] )

  re_match( url , ref)

  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

#  Allow users to write on scratch/<username> folder with wlcg profile
allow {

  input.claims.aud == "https://wlcg.cern.ch/jwt/v1/any"

  sub := input.claims.sub
  username :=  replace(split(lower(data.roles.usermap[sub]),"@")[0], "_", "")

  ref := input.conditions.Referer[_]

  url := concat("/", ["^https://.*/minio/scratch",username,".*$"] )

  re_match( url , ref)

  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Allow users to write on scratch/<username> folder
allow {

  username := replace(split(lower(input.account),"@")[0], "_", "")
  ref := input.conditions.Referer[_]

  url := concat("/", ["^https://.*/minio/scratch",username,".*$"] )

  re_match( url , ref)

  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

#### No referer included in request
# Allow users to write on scratch/<username> folder
allow {
  grp := input.claims.groups
  grp[_] == data.roles.permissions.user_groups[_]

  input.bucket == "scratch"

  username := replace(split(lower(input.claims.preferred_username),"@")[0], "_", "")
  
  obj := input.object

  regex := concat("", ["^",username,"/.*$"] )

  re_match( regex , obj )

  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Allow users to write on scratch/<username> folder with wlcg profile
allow {

  sub := input.claims.sub
  username := replace(split(lower(data.roles.usermap[sub]),"@")[0], "_", "")
  
  input.bucket == "scratch"

  obj := input.object

  regex := concat("", ["^",username,"/.*$"] )

  re_match( regex , obj )

  startswith(input.claims.iss, data.roles.permissions.issuer)
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

# Allow users to write on scratch/<username> folder
allow {

  username := replace(split(lower(input.account),"@")[0], "_", "")

  input.bucket == "scratch"

  obj := input.object

  regex := concat("", ["^",username,"/.*$"] )

  re_match( regex , obj )

  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}
