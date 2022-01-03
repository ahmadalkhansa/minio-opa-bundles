package http.base.authz


test_post_allowed {
  allow with input as { "claims": { "preferred_username": "dciangot",
                                    "iss": data.roles.permissions.issuer,
                                    "wlcg.groups": ["/herd/minio-admin"]
                                  },
                        "bucket": "dciangot",
                        "action": "admin:ServerTrace"
                      }
}

test_post_nogroup_not_allowed {
  not allow with input as { "claims": { "preferred_username": "dciangot",
                                        "iss": data.roles.permissions.issuer
                                      },
                            "bucket": "dciangot",
                            "action": "admin:ServerTrace"
                          }
}
