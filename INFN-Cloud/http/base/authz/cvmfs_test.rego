package http.base.authz

test_read_cvmfs_allowed {
  allow with input as { 
                        "account": "cvmfspublisher",
                        "object": "dciangot/cvmfs/testme",
                        "action": "s3:GetObject"
                      }
}

test_listbucket_cvmfs_allowed {
  allow with input as { 
                        "account": "cvmfspublisher",
                        "bucket": "dciangot",
                        "action": "s3:ListBucket"
                      }
}
