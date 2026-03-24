# TODO

## Future Tasks

- [ ] Service account bind for search — request dedicated LDAP service account from IT for use when user-bound search is not sufficient
- [ ] Google Workspace LDAP — test `MutualAuth` TLS path with a client cert from Google Admin
- [ ] Search for groups — add a `search_groups` function to fetch group membership details beyond just the DN
- [ ] Handle LDAP referrals — follow referrals automatically rather than falling back to basic user
- [ ] Additional domain support — test `additional_domains` in `Config` for multi-domain environments
- [ ] CI integration tests — decide how to handle credentials in CI (secrets, mock LDAP, etc.)
- [ ] Web test interface — simple web app that uses this library to provide an HTML form for testing LDAP auth against a given server
