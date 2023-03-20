package http.base.authz

test_read_cvmfs_allowed {
  allow with input as { 
                        "account": "cvmfs_publisher",
                        "object": "dciangot/cvmfs/testme",
                        "action": "s3:GetObject"
                      }
}