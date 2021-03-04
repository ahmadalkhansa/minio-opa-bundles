package http.base.authz
import input
import data

allow {
  username := split(lower(input.claims.preferred_username),"@")[0]
  input.bucket == username
  input.claims.iss == "https://iam.cloud.infn.it/"
  permissions := data.roles.permissions.user
  permissions[_] == {"action": input.action}
}

