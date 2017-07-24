initSidebarItems({"enum":[["Error","Authentication errors"]],"fn":[["missing_authorization","Convenience function to respond with a missing authorization error"]],"mod":[["simple","Simple authenticator module"]],"struct":[["AuthenticationResult","Result from a successful authentication operation"],["Authorization","`Authorization` HTTP Request Header"],["LdapAuthenticator","LDAP based authenticator"],["NoOp","A \"no-op\" authenticator that lets everything through. DO NOT USE THIS IN PRODUCTION."],["NoOpConfiguration","Configuration for the `no-op` authenticator. Nothing to configure."]],"trait":[["Authenticator","Authenticator trait to be implemented by identity provider (idp) adapters to provide authentication. Each idp may support all the schemes supported, or just one."],["AuthenticatorConfiguration","Configuration for the associated type `Authenticator`. [`rowdy::Configuration`] expects its `authenticator` field to implement this trait. Before launching, `rowdy` will attempt to make an `Authenticator` based off the configuration by calling the `make_authenticator` method."]],"type":[["Basic","Re-exported [`hyper::header::Basic`]."],["BasicAuthenticator","A typedef for an `Authenticator` trait object that requires HTTP Basic authentication"],["Bearer","Re-exported [`hyper::header::Bearer`]."],["BearerAuthenticator","A typedef for an `Authenticator` trait object that requires Bearer authentication."],["Scheme","Re-exported [`hyper::header::Scheme`]"],["StringAuthenticator","A typedef for an `Authenticator` trait object that uses an arbitrary string"]]});