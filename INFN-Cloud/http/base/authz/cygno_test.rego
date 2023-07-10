package http.base.authz

test_listbucket_cygno_allowed {
  allow with input as {
                        "account": "cygnodm",
                        "bucket": "cygno-analysis",
                        "action": "s3:ListBucket"
                      }
}

test_post_cygnus_allowed {
  allow with input as { "claims": { "preferred_username": "stalio",
                                    "groups": ["cygno-users"],
                                    "iss": data.roles.permissions.issuer
                                  },
                        "bucket": "cygno-data",
                        "action": "s3:ListBucket"
                      }
}


test_post_cygnus_not_allowed {
  not allow with input as { "claims": { "preferred_username": "dciangot",
                                    "groups": ["cygno2"],
                                    "iss": data.roles.permissions.issuer
                                  },
                        "bucket": "cygnus",
                        "action": "s3:ListBucket"
                      }
}
