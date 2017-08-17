#![allow(unused_qualifications)]
//! MySql authenticator module
use argon2rs;

use diesel::prelude::*;
use diesel::mysql::MysqlConnection;
use diesel::result::ConnectionError;

// FIXME: Remove dependency on `ring`.
use ring::test;
use ring::constant_time::verify_slices_are_equal;

use {Error, JsonMap, JsonValue};
use super::{AuthenticationResult, Basic};

/// Error mapping for `ConnectionError`
impl From<ConnectionError> for Error {
    fn from(e: ConnectionError) -> Error {
        Error::GenericError(e.to_string())
    }
}

// Code for conversion to hex stolen from rustc-serialize:
// https://doc.rust-lang.org/rustc-serialize/src/rustc_serialize/hex.rs.html

/// MySql user record
#[derive(Queryable)]
pub struct User {
    username: String,
    pw_hash: String,
    salt: String,
}

/// A simple authenticator that uses a MySql backed user database.
///
/// Requires the `mysql_authenticator` feature, which is enabled by default.
///
/// The user database should be a MySql database with a table of the following format:
/// username(VARCHAR(255)), pw_hash(VARCHAR(255)), salt(VARCHAR(255))
///
/// # Password Hashing
/// See `MySqlAuthenticator::hash_password` for the implementation of password hashing.
/// The password is hashed using the [`argon2i`](https://github.com/p-h-c/phc-winner-argon2) algorithm with
/// a randomly generated salt.
pub struct MySqlAuthenticator {
    database_uri: String
}

static CHARS: &'static [u8] = b"0123456789abcdef";

impl MySqlAuthenticator {
    /// Create a new `MySqlAuthenticator` with a database connection
    ///
    pub fn new(uri: String) -> Self {
        MySqlAuthenticator {database_uri: uri}
    }

    /// Create a new `MySqlAuthenticator` with a database config
    ///
    pub fn with_configuration(host: &str, port: u16, database: &str, user: &str, pass: &str) -> Result<Self, Error> {
        let database_uri: String = String::from(
            format!("mysql://{}:{}@{}:{}/{}", user, pass, host, port, database)
        );
        let authenticator = MySqlAuthenticator{database_uri};
        match authenticator.test_connection() {
            Ok(_) => Ok(authenticator),
            Err(e) => Err(Error::GenericError(e.to_string())),
        }
    }

    fn test_connection(&self) -> Result<&'static str, Error> {
        let _ = self.connect()?;
        Ok("Connection successful")
    }

    /// Connects to MySql Server
    fn connect(&self) -> Result<MysqlConnection, Error> {
        debug_!("Connecting to Mysql server");
        let connection = MysqlConnection::establish(&self.database_uri)?;
        Ok(connection)
    }

    /// Search for the specified user entry
    fn search(
        &self,
        connection: &MysqlConnection,
        search_user: &str
    ) -> Result<Vec<User>, Error> {
        use super::schema::users::dsl::*;
        let results = users.filter(username.eq(search_user))
            .load::<User>(connection)
            .map_err(|e| Error::GenericError(
                    format!("Database query failed: {}", e)
            ))?;
        Ok(results)
    }

    /// Hash a password with the salt. See struct level documentation for the algorithm used.
    // TODO: Write an "example" tool to salt easily
    pub fn hash_password(password: &str, salt: &[u8]) -> Result<String, Error> {
        Ok(hex_dump(
            Self::hash_password_digest(password, salt)?.as_ref(),
        ))
    }

    /// Verify that some user with the provided password exists in the CSV database, and the password is correct.
    /// Returns the payload to be included in a refresh token if successful
    pub fn verify(
        &self,
        username: &str,
        password: &str,
        include_refresh_payload: bool,
    ) -> Result<AuthenticationResult, Error> {
        let user = {
            let connection = self.connect()?;
            let mut user = self.search(&connection, username).map_err(|_e| {
                super::Error::AuthenticationFailure
            })?;
            if user.len() != 1 {
                Err(super::Error::AuthenticationFailure)?;
            }

            user.pop().unwrap() // safe to unwrap
        };
        if username != user.username {
            return Err(Error::Auth(super::Error::AuthenticationFailure));
        }
        let hash = test::from_hex(&user.pw_hash)?;
        let salt = test::from_hex(&user.salt)?;

        let actual_password_digest = Self::hash_password_digest(password, &salt)?;
        if !verify_slices_are_equal(actual_password_digest.as_ref(), &*hash).is_ok() {
            Err(Error::Auth(super::Error::AuthenticationFailure))
        } else {
            let refresh_payload = if include_refresh_payload {
                let mut map = JsonMap::with_capacity(2);
                let _ = map.insert("user".to_string(), From::from(username));
                let _ = map.insert("password".to_string(), From::from(password));
                Some(JsonValue::Object(map))
            } else {
                None
            };

            Ok(AuthenticationResult {
                subject: username.to_string(),
                private_claims: JsonValue::Object(JsonMap::new()),
                refresh_payload,
            })
        }
    }

    fn hash_password_digest(password: &str, salt: &[u8]) -> Result<Vec<u8>, Error> {
        let bytes = password.as_bytes();
        let mut out = vec![0; argon2rs::defaults::LENGTH];
        let argon2 = argon2rs::Argon2::default(argon2rs::Variant::Argon2i);
        argon2.hash(&mut out, bytes, salt, &[], &[]);
        Ok(out)
    }
}

impl super::Authenticator<Basic> for MySqlAuthenticator {
    fn authenticate(
        &self,
        authorization: &super::Authorization<Basic>,
        include_refresh_payload: bool,
    ) -> Result<AuthenticationResult, Error> {
        let username = authorization.username();
        let password = authorization.password().unwrap_or_else(|| "".to_string());
        self.verify(&username, &password, include_refresh_payload)
    }

    fn authenticate_refresh_token(&self, refresh_payload: &JsonValue) -> Result<AuthenticationResult, ::Error> {
        match *refresh_payload {
            JsonValue::Object(ref map) => {
                let user = map.get("user")
                    .ok_or_else(|| super::Error::AuthenticationFailure)?
                    .as_str()
                    .ok_or_else(|| super::Error::AuthenticationFailure)?;
                let password = map.get("password")
                    .ok_or_else(|| super::Error::AuthenticationFailure)?
                    .as_str()
                    .ok_or_else(|| super::Error::AuthenticationFailure)?;
                self.verify(user, password, false)
            }
            _ => Err(super::Error::AuthenticationFailure)?,
        }
    }
}

/// (De)Serializable configuration for `MySqlAuthenticator`. This struct should be included
/// in the base `Configuration`.
/// # Examples
/// ```json
/// {
///     "host": "localhost",
///     "port": "3306",  // default if not specified
///     "database": "auth_users",
///     "user": "auth_user",
///     "password": "password"
/// }
/// ```
#[derive(Eq, PartialEq, Serialize, Deserialize, Debug)]
pub struct MySqlAuthenticatorConfiguration {
    /// Host for the MySql database manager - domain name or IP
    pub host: String,
    /// MySql database port - default 3306
    #[serde(default = "default_port")]
    pub port: u16,
    /// MySql database
    pub database: String,
    /// MySql user
    pub user: String,
    /// MySql password
    pub password: String,
}

fn default_port() -> u16 {
    3306
}

impl super::AuthenticatorConfiguration<Basic> for MySqlAuthenticatorConfiguration {
    type Authenticator = MySqlAuthenticator;

    fn make_authenticator(&self) -> Result<Self::Authenticator, ::Error> {
        Ok(MySqlAuthenticator::with_configuration(
            &self.host,
            self.port,
            &self.database,
            &self.user,
            &self.password,
        )?)
    }
}

/// Convenience function to hash passwords from some users and provided passwords
/// The salt length must be between 8 and 2^32 - 1 bytes.
/*
pub fn hash_passwords(users: &HashMap<String, String>, salt_len: usize) -> Result<Users, Error> {
    let mut hashed: Users = HashMap::new();
    for (user, password) in users {
        let salt = generate_salt(salt_len)?;
        let hash = MySqlAuthenticator::hash_password_digest(password, &salt)?;
        let _ = hashed.insert(user.to_string(), (hash, salt));
    }
    Ok(hashed)
}
*/

/// Generate a new random salt based on the configured salt length
/*
pub fn generate_salt(salt_length: usize) -> Result<Vec<u8>, Error> {
    let mut salt: Vec<u8> = vec![0; salt_length];
    jwa::rng().fill(&mut salt).map_err(|e| e.to_string())?;
    Ok(salt)
}
*/

fn hex_dump(bytes: &[u8]) -> String {
    let mut v = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes.iter() {
        v.push(CHARS[(byte >> 4) as usize]);
        v.push(CHARS[(byte & 0xf) as usize]);
    }

    unsafe { String::from_utf8_unchecked(v) }
}

#[cfg(test)]
mod tests {
    use auth::Authenticator;
    use super::*;

    fn make_authenticator() -> MySqlAuthenticator {
        not_err!(MySqlAuthenticator::with_configuration(
            "localhost",
            3306,
            "rowdy",
            "root",
            "",
        ))
    }

    #[test]
    fn test_hex_dump() {
        assert_eq!(hex_dump(b"foobar"), "666f6f626172");
    }

    #[test]
    fn test_hex_dump_all_bytes() {
        for i in 0..256 {
            assert_eq!(hex_dump(&[i as u8]), format!("{:02x}", i));
        }
    }

    #[test]
    fn hashing_is_done_correctly() {
        let hashed_password = not_err!(MySqlAuthenticator::hash_password("password", &[0; 32]));
        assert_eq!(
            "e6e1111452a5574d8d64f6f4ba6fabc86af5c45c341df1eb23026373c41d24b8",
            hashed_password
        );
    }

    #[test]
    fn hashing_is_done_correctly_for_unicode() {
        let hashed_password = not_err!(MySqlAuthenticator::hash_password(
            "冻住，不许走!",
            &[0; 32],
        ));
        assert_eq!(
            "b400a5eea452afcc67a81602f28012e5634404ddf1e043d6ff1df67022c88cd2",
            hashed_password
        );
    }

    #[test]
    fn authentication_with_username_and_password() {
        let authenticator = make_authenticator();

        let _ = not_err!(authenticator.verify("foobar", "password", false));

        let result = not_err!(authenticator.verify("mei", "冻住，不许走!", false));
        assert!(result.refresh_payload.is_none()); // refresh refresh_payload is not provided when not requested
    }

    #[test]
    fn authentication_with_refresh_payload() {
        let authenticator = make_authenticator();

        let result = not_err!(authenticator.verify("foobar", "password", true));
        assert!(result.refresh_payload.is_some()); // refresh refresh_payload is provided when requested

        let result = not_err!(authenticator.authenticate_refresh_token(result.refresh_payload.as_ref().unwrap()));
        assert!(result.refresh_payload.is_none());
    }

    #[test]
    fn mysql_authenticator_configuration_deserialization() {
        use serde_json;
        use auth::AuthenticatorConfiguration;

        let json = r#"{
            "host": "localhost",
            "port": 3306,
            "database": "rowdy",
            "user": "root",
            "password": ""
        }"#;

        let deserialized: MySqlAuthenticatorConfiguration = not_err!(serde_json::from_str(json));
        let expected_config = MySqlAuthenticatorConfiguration {
            host: "localhost".to_string(),
            port: 3306,
            database: "rowdy".to_string(),
            user: "root".to_string(),
            password: "".to_string(),
        };
        assert_eq!(deserialized, expected_config);

        let _ = not_err!(expected_config.make_authenticator());
    }
}
