package http.base.authz
import input
import data

allow {

  input.account == "cvmfs_publisher"

  obj := input.object

  regex := concat("", ["^.*/cvmfs/.*$"] ) 

  re_match( regex , obj )

  permissions := data.roles.permissions.scratch
  permissions[_] == {"action": input.action}
}


allow {

  input.account == "cvmfs_publisher"

  input.action == "s3:ListBucket"
}

