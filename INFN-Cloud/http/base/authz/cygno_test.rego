package http.base.authz

test_post_cygnus_allowed {
  allow with input as { "claims": { "preferred_username": "dciangot",
                                    "groups": ["cygno"],
                                    "iss": data.roles.permissions.issuer
                                  },
                        "bucket": "cygnus",
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