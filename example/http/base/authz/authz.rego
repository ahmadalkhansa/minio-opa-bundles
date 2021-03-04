package http.base.authz
import input
import data

default allow = false


allow {
  username := split(lower(input.claims.preferred_username),"@")[0]
  input.bucket == username
  input.claims.iss == "https://iam-demo.cloud.cnaf.infn.it/"
  rl := data.roles.permissions.user
  rl[_] == {"action": input.action}
}
