package http.base.authz

test_read_cvmfs_allowed {
  not allow with input as { 
                        "account": "cvmfspublisher",
                        "object": "cvmfs/testme",
                        "action": "s3:GetObject"
                      }
}

test_listbucket_cvmfs_allowed {
  not allow with input as { 
                        "account": "cvmfspublisher",
                        "bucket": "dciangot",
                        "action": "s3:ListBucket"
                      }
}
