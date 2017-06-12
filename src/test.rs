macro_rules! not_err {
    ($e:expr) => (match $e {
        Ok(e) => e,
        Err(e) => panic!("{} failed with {:?}", stringify!($e), e),
    })
}

macro_rules! is_err {
    ($e:expr) => (match $e {
        Ok(e) => panic!("{} did not return with an error, but with {:?}", stringify!($e), e),
        Err(e) => e,
    })
}

macro_rules! not_none {
    ($e:expr) => (match $e {
        Some(e) => e,
        None => panic!("{} failed with None", stringify!($e)),
    })
}

macro_rules! assert_matches {
    ($e: expr, $p: pat) => (assert_matches!($e, $p, ()));
    ($e: expr, $p: pat, $f: expr) => (match $e {
        $p => $f,
        e => panic!("{}: Expected pattern {} \ndoes not match {:?}", stringify!($e), stringify!($p), e)
    })
}

macro_rules! assert_matches_non_debug {
    ($e: expr, $p: pat) => (assert_matches_non_debug!($e, $p, ()));
    ($e: expr, $p: pat, $f: expr) => (match $e {
        $p => $f,
        _ => panic!("{}: Expected pattern {} \ndoes not match {}", stringify!($e), stringify!($p), stringify!($e))
    })
}
