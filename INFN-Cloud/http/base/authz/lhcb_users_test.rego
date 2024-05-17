package http.base.authz

test_post_lhcbusers_allowed {
  not allow with input as { "claims": { "preferred_username": "matteo_barbetti",
                                    "groups": ["users/lhcb"],
                                    "iss": data.roles.permissions.issuer
                                  },
                        "bucket": "lhcb-data",
                        "action": "s3:PutObject",
                        "object": "matteobarbetti/sadasd.root"
                      }
}


test_post_lhcbusers_not_allowed {
  not allow with input as { "claims": { "preferred_username": "dciangot",
                                    "groups": ["users/lh"],
                                    "iss": data.roles.permissions.issuer
                                  },
                        "bucket": "lhcb-data",
                        "action": "s3:ListBucket"
                      }
}
