package http.cygno.authz

test_post_allowed {
  allow with input as { "claims": { "preferred_username": "dciangot",
                                    "groups": ["Cygno"],
                                    "iss": "https://iam.cloud.infn.it/"
                                  },
                        "bucket": "cygnus",
                        "action": "s3:ListBucket"
                      }
}


test_post_not_allowed {
  not allow with input as { "claims": { "preferred_username": "dciangot",
                                    "groups": ["Cygno2"],
                                    "iss": "https://iam.cloud.infn.it/"
                                  },
                        "bucket": "cygnus",
                        "action": "s3:ListBucket"
                      }
}