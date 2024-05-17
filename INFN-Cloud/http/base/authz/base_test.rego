package http.base.authz


test_post_allowed {
  not allow with input as { "claims": { "preferred_username": "matteo_barbetti",
                                    "iss": data.roles.permissions.issuer,
                                    "groups": ["end-users-catchall"]
                                  },
                        "bucket": "matteobarbetti",
                        "action": "s3:ListBucket"
                      }
}

test_post_wlcg_allowed {
  not allow with input as { "claims": { "sub": "2f8dcc16-c636-4a56-9ada-63b761d89286",
                                    "iss": data.roles.permissions.issuer,
                                    "aud": "https://wlcg.cern.ch/jwt/v1/any",
                                  },
                        "bucket": "ciangottini",
                        "action": "s3:ListBucket"
                      }
}

test_post_nogroup_not_allowed {
  not allow with input as { "claims": { "preferred_username": "dciangot",
                                        "iss": data.roles.permissions.issuer
                                      },
                            "bucket": "dciangot",
                            "action": "s3:ListBucket"
                          }
}

test_post_not_allowed {
  not allow with input as { "claims": { "preferred_username": "dciangot",
                                        "iss": data.roles.permissions.issuer
                                      },
                            "bucket": "spigaa",
                            "action": "s3:ListBucket"
                          }
}
