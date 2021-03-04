package http.base.authz


test_post_allowed {
  allow with input as { "claims": { "preferred_username": "dciangot",
                                    "iss": "https://iam-demo.cloud.cnaf.infn.it/"
                                  },
                        "bucket": "dciangot",
                        "action": "s3:ListBucket"
                      }
}

test_post_allowed {
  not allow with input as { "claims": { "preferred_username": "dciangot",
                                        "iss": "https://iam-demo.cloud.cnaf.infn.it/"
                                      },
                            "bucket": "spigaa",
                            "action": "s3:ListBucket"
                          }
}
