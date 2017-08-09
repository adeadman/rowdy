//! MySQL authenticator module
use std::collections::HashMap;

use argon2rs;
use mysql as my;

use jwt::jwa::{self, SecureRandom};
// FIXME: Remove dependency on `ring`.
use ring::test;
use ring::constant_time::verify_slices_are_equal;

use {Error, JsonValue, JsonMap};
use super::{Basic, AuthenticationResult};

// Code for conversion to hex stolen from rustc-serialize:
// https://doc.rust-lang.org/rustc-serialize/src/rustc_serialize/hex.rs.html

/// Typedef for the internal representation of a users database. The keys are the usernames, and the values
/// are a tuple of the password hash and salt.
pub type Users = HashMap<String, (Vec<u8>, Vec<u8>)>;

/// MySQL user record
#[derive(Debug, PartialEq, Eq)]
struct UserRecord{
    username: Option<String>,
    pw_hash: Option<String>,
    salt: Option<String>,
}

/// A simple authenticator that uses a MySQL backed user database.
///
/// Requires the `mysql_authenticator` feature, which is enabled by default.
///
/// The user database should be a MySQL database with a table of the following format:
/// username(VARCHAR(255)), pw_hash(VARCHAR(255)), salt(VARCHAR(255))
///
/// # Password Hashing
/// See `MySQLAuthenticator::hash_password` for the implementation of password hashing.
/// The password is hashed using the [`argon2i`](https://github.com/p-h-c/phc-winner-argon2) algorithm with
/// a randomly generated salt.
pub struct MySQLAuthenticator {
    users: Users,
}

static CHARS: &'static [u8] = b"0123456789abcdef";

impl MySQLAuthenticator {
    /// Create a new `MySQLAuthenticator` with the provided database credentials
    ///
    pub fn new(pool: my::Pool) -> Result<Self, Error> {
        Ok(MySQLAuthenticator { users: Self::users_from_db(pool)? })
    }

    /// Create a new `MySQLAuthenticator` with a database config
    ///
    pub fn with_configuration(host: &str, port: u16, database: &str, user: &str, pass: &str) -> Result<Self, Error> {
        let pool = my::Pool::new(format!("mysql://{}:{}@{}:{}/{}", user, pass, host, port, database)).unwrap();
        Self::new(pool)
    }

    fn users_from_db(pool: my::Pool) -> Result<Users, Error> {
        // Parse the records, and look for errors
        let selected_users: Vec<UserRecord> =
            pool.prep_exec("SELECT username, pw_hash, salt from auth_users", ())
            .map(|result| {
                result.map(|x| x.unwrap()).map(|row| {
                    let (username, pw_hash, salt) = my::from_row(row);
                    UserRecord{
                        username: username,
                        pw_hash: pw_hash,
                        salt: salt,
                    }
                }).collect()
            }).unwrap();

        type ParsedRecordBytes = Vec<Result<(String, Vec<u8>, Vec<u8>), String>>;
        // Decode the hex values from users
        let (users, errors): (ParsedRecordBytes, ParsedRecordBytes) = selected_users
            .into_iter()
            .map(|r| {
                let UserRecord{username, pw_hash, salt} = r;

                let user_string = username.unwrap();
                let salt_bytes = match salt {
                    Some(s) => test::from_hex(&s)?,
                    None    => "_".as_bytes().to_vec(),
                };
                let hash_bytes = match pw_hash {
                    Some(s) => test::from_hex(&s)?,
                    None    => "_".as_bytes().to_vec(),
                };
                Ok((user_string, hash_bytes, salt_bytes))
            })
            .partition(Result::is_ok);

        if !errors.is_empty() {
            let errors: Vec<String> = errors.into_iter().map(|r| r.unwrap_err()).collect();
            Err(errors.join("; "))?;
        }

        let users: Users = users
            .into_iter()
            .map(|r| {
                let (username, hash, salt) = r.unwrap(); // safe to unwrap
                (username, (hash, salt))
            })
            .collect();

        Ok(users)
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
        match self.users.get(username) {
            None => Err(Error::Auth(super::Error::AuthenticationFailure)),
            Some(&(ref hash, ref salt)) => {
                let actual_password_digest = Self::hash_password_digest(password, salt)?;
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

impl super::Authenticator<Basic> for MySQLAuthenticator {
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

/// (De)Serializable configuration for `MySQLAuthenticator`. This struct should be included
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
pub struct MySQLAuthenticatorConfiguration {
    /// Host for the MySQL database manager - domain name or IP
    pub host: String,
    /// MySQL database port - default 3306
    #[serde(default = "default_port")]
    pub port: u16,
    /// MySQL database
    pub database: String,
    /// MySQL user
    pub user: String,
    /// MySQL password
    pub password: String
}

fn default_port() -> u16 {
    3306
}

impl super::AuthenticatorConfiguration<Basic> for MySQLAuthenticatorConfiguration {
    type Authenticator = MySQLAuthenticator;

    fn make_authenticator(&self) -> Result<Self::Authenticator, ::Error> {
        Ok(MySQLAuthenticator::with_configuration(
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
pub fn hash_passwords(users: &HashMap<String, String>, salt_len: usize) -> Result<Users, Error> {
    let mut hashed: Users = HashMap::new();
    for (user, password) in users {
        let salt = generate_salt(salt_len)?;
        let hash = MySQLAuthenticator::hash_password_digest(password, &salt)?;
        let _ = hashed.insert(user.to_string(), (hash, salt));
    }
    Ok(hashed)
}

/// Generate a new random salt based on the configured salt length
pub fn generate_salt(salt_length: usize) -> Result<Vec<u8>, Error> {
    let mut salt: Vec<u8> = vec![0; salt_length];
    jwa::rng().fill(&mut salt).map_err(|e| e.to_string())?;
    Ok(salt)
}

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

    fn make_authenticator() -> MySQLAuthenticator {
        not_err!(MySQLAuthenticator::with_configuration(
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
        let hashed_password = not_err!(MySQLAuthenticator::hash_password("password", &[0; 32]));
        assert_eq!(
            "e6e1111452a5574d8d64f6f4ba6fabc86af5c45c341df1eb23026373c41d24b8",
            hashed_password
        );
    }

    #[test]
    fn hashing_is_done_correctly_for_unicode() {
        let hashed_password = not_err!(MySQLAuthenticator::hash_password(
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
        let expected_keys = vec!["foobar".to_string(), "mei".to_string()];
        let mut actual_keys: Vec<String> = authenticator.users.keys().cloned().collect();
        actual_keys.sort();
        assert_eq!(expected_keys, actual_keys);

        let _ = not_err!(authenticator.verify("foobar", "password", false));

        let result = not_err!(authenticator.verify("mei", "冻住，不许走!", false));
        assert!(result.refresh_payload.is_none()); // refresh refresh_payload is not provided when not requested
    }

    #[test]
    fn authentication_with_refresh_payload() {
        let authenticator = make_authenticator();

        let result = not_err!(authenticator.verify("foobar", "password", true));
        assert!(result.refresh_payload.is_some()); // refresh refresh_payload is provided when requested

        let result = not_err!(authenticator.authenticate_refresh_token(
            result.refresh_payload.as_ref().unwrap(),
        ));
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

        let deserialized: MySQLAuthenticatorConfiguration = not_err!(serde_json::from_str(json));
        let expected_config = MySQLAuthenticatorConfiguration {
            host: "localhost".to_string(),
            port: 3306,
            database: "rowdy".to_string(),
            user: "root".to_string(),
            password: "".to_string()
        };
        assert_eq!(deserialized, expected_config);

        let _ = not_err!(expected_config.make_authenticator());
    }
}
