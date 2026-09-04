//! ESMTP command parsing.
//!
//! Split out from the session so the grammar can be tested directly, which is
//! where most real-world SMTP interoperability bugs live.

/// A parsed client command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Ehlo(String),
    Helo(String),
    Mail {
        /// Envelope sender; empty for the null sender (`MAIL FROM:<>`).
        address: String,
        /// Value of the `SIZE=` parameter, when supplied.
        size: Option<u64>,
    },
    Rcpt {
        address: String,
    },
    Data,
    Rset,
    Noop,
    Quit,
    Vrfy,
    Expn,
    Help,
    StartTls,
    Auth {
        mechanism: String,
        /// Initial response sent alongside the command.
        initial: Option<String>,
    },
    /// Recognised as a verb we do not implement.
    Unimplemented(String),
    /// Not a known verb at all.
    Unknown(String),
    Empty,
}

/// A syntax error, carrying the exact reply the session should send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    pub code: u16,
    pub enhanced: &'static str,
    pub message: String,
}

impl CommandError {
    fn new(code: u16, enhanced: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            enhanced,
            message: message.into(),
        }
    }

    fn syntax(message: impl Into<String>) -> Self {
        Self::new(501, "5.5.4", message)
    }
}

/// Parses one command line (already stripped of its CRLF).
pub fn parse(line: &[u8]) -> Result<Command, CommandError> {
    // Commands are ASCII; a lossy conversion cannot corrupt anything we act
    // on, and keeps a malformed byte from killing the session.
    let text = String::from_utf8_lossy(line);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Command::Empty);
    }

    let (verb, rest) = match trimmed.find(char::is_whitespace) {
        Some(index) => (&trimmed[..index], trimmed[index..].trim_start()),
        None => (trimmed, ""),
    };
    let upper = verb.to_ascii_uppercase();

    match upper.as_str() {
        "EHLO" => {
            if rest.is_empty() {
                return Err(CommandError::syntax("EHLO requires a domain name"));
            }
            Ok(Command::Ehlo(first_token(rest).to_string()))
        }
        "HELO" => {
            if rest.is_empty() {
                return Err(CommandError::syntax("HELO requires a domain name"));
            }
            Ok(Command::Helo(first_token(rest).to_string()))
        }
        "MAIL" => parse_mail(rest),
        "RCPT" => parse_rcpt(rest),
        "DATA" => Ok(Command::Data),
        "RSET" => Ok(Command::Rset),
        "NOOP" => Ok(Command::Noop),
        "QUIT" => Ok(Command::Quit),
        "VRFY" => Ok(Command::Vrfy),
        "EXPN" => Ok(Command::Expn),
        "HELP" => Ok(Command::Help),
        "STARTTLS" => Ok(Command::StartTls),
        "AUTH" => parse_auth(rest),
        "BDAT" | "ETRN" | "ATRN" | "TURN" | "SAML" | "SOML" | "SEND" => {
            Ok(Command::Unimplemented(upper))
        }
        _ => Ok(Command::Unknown(upper)),
    }
}

fn first_token(input: &str) -> &str {
    input.split_whitespace().next().unwrap_or("")
}

fn parse_mail(rest: &str) -> Result<Command, CommandError> {
    let after = expect_keyword(rest, "FROM").ok_or_else(|| {
        CommandError::syntax("expected `MAIL FROM:<address>`")
    })?;
    let (address, parameters) = split_path(after)?;

    let mut size = None;
    for (key, value) in parameters {
        match key.as_str() {
            "SIZE" => {
                size = value.as_deref().and_then(|v| v.parse::<u64>().ok());
                if size.is_none() {
                    return Err(CommandError::new(
                        501,
                        "5.5.4",
                        "the SIZE parameter must be a number",
                    ));
                }
            }
            // Accepted and ignored: the message body is relayed verbatim, so
            // the upstream relay sees exactly what the client sent.
            "BODY" | "SMTPUTF8" | "RET" | "ENVID" | "AUTH" | "REQUIRETLS" => {}
            other => {
                return Err(CommandError::new(
                    555,
                    "5.5.4",
                    format!("unsupported MAIL parameter `{other}`"),
                ));
            }
        }
    }

    Ok(Command::Mail { address, size })
}

fn parse_rcpt(rest: &str) -> Result<Command, CommandError> {
    let after = expect_keyword(rest, "TO")
        .ok_or_else(|| CommandError::syntax("expected `RCPT TO:<address>`"))?;
    let (address, parameters) = split_path(after)?;

    if address.is_empty() {
        return Err(CommandError::new(
            501,
            "5.1.3",
            "a recipient address is required",
        ));
    }

    for (key, _) in parameters {
        match key.as_str() {
            "NOTIFY" | "ORCPT" | "RRVS" => {}
            other => {
                return Err(CommandError::new(
                    555,
                    "5.5.4",
                    format!("unsupported RCPT parameter `{other}`"),
                ));
            }
        }
    }

    Ok(Command::Rcpt { address })
}

fn parse_auth(rest: &str) -> Result<Command, CommandError> {
    if rest.is_empty() {
        return Err(CommandError::new(
            501,
            "5.5.4",
            "AUTH requires a mechanism",
        ));
    }
    let mut parts = rest.split_whitespace();
    let mechanism = parts.next().unwrap_or("").to_ascii_uppercase();
    let initial = parts.next().map(|value| value.to_string());
    Ok(Command::Auth {
        mechanism,
        initial,
    })
}

/// Matches `KEYWORD:` at the start of `input`, tolerating the space that some
/// clients insert before the colon.
fn expect_keyword<'a>(input: &'a str, keyword: &str) -> Option<&'a str> {
    let trimmed = input.trim_start();
    // Compared as bytes so a multi-byte character at the start cannot panic on
    // a slice boundary. A successful ASCII match also guarantees that
    // `keyword.len()` is a valid char boundary.
    let bytes = trimmed.as_bytes();
    if bytes.len() < keyword.len() {
        return None;
    }
    if !bytes[..keyword.len()].eq_ignore_ascii_case(keyword.as_bytes()) {
        return None;
    }
    let after = trimmed[keyword.len()..].trim_start();
    after.strip_prefix(':')
}

/// Splits `<address> KEY=VALUE ...` into the address and its parameters.
fn split_path(input: &str) -> Result<(String, Vec<(String, Option<String>)>), CommandError> {
    let trimmed = input.trim_start();

    let (address, remainder) = if let Some(open) = trimmed.strip_prefix('<') {
        match open.find('>') {
            Some(close) => (&open[..close], &open[close + 1..]),
            None => {
                return Err(CommandError::syntax(
                    "unterminated address: expected a closing `>`",
                ))
            }
        }
    } else {
        // Some clients omit the angle brackets; accept the bare form.
        match trimmed.find(char::is_whitespace) {
            Some(index) => (&trimmed[..index], &trimmed[index..]),
            None => (trimmed, ""),
        }
    };

    let address = strip_source_route(address.trim());
    let mut parameters = Vec::new();
    for token in remainder.split_whitespace() {
        match token.split_once('=') {
            Some((key, value)) => {
                parameters.push((key.to_ascii_uppercase(), Some(value.to_string())))
            }
            None => parameters.push((token.to_ascii_uppercase(), None)),
        }
    }

    Ok((address, parameters))
}

/// Drops the obsolete source route form `@relay:user@host`.
fn strip_source_route(address: &str) -> String {
    if address.starts_with('@') {
        if let Some((_, rest)) = address.split_once(':') {
            return rest.trim().to_string();
        }
    }
    address.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(line: &str) -> Command {
        parse(line.as_bytes()).unwrap_or_else(|error| panic!("{line:?} -> {error:?}"))
    }

    #[test]
    fn greeting_commands_are_case_insensitive() {
        assert_eq!(parsed("EHLO mautic.local"), Command::Ehlo("mautic.local".into()));
        assert_eq!(parsed("ehlo mautic.local"), Command::Ehlo("mautic.local".into()));
        assert_eq!(parsed("HeLo mautic.local"), Command::Helo("mautic.local".into()));
        assert!(parse(b"EHLO").is_err());
    }

    #[test]
    fn simple_verbs_parse() {
        assert_eq!(parsed("DATA"), Command::Data);
        assert_eq!(parsed("data"), Command::Data);
        assert_eq!(parsed("RSET"), Command::Rset);
        assert_eq!(parsed("NOOP"), Command::Noop);
        assert_eq!(parsed("NOOP with junk"), Command::Noop);
        assert_eq!(parsed("QUIT"), Command::Quit);
        assert_eq!(parsed(""), Command::Empty);
        assert_eq!(parsed("   "), Command::Empty);
        assert_eq!(parsed("FROB"), Command::Unknown("FROB".into()));
        assert_eq!(parsed("BDAT 100"), Command::Unimplemented("BDAT".into()));
    }

    #[test]
    fn mail_from_accepts_the_common_shapes() {
        let expected = Command::Mail {
            address: "campaigns@acme.io".into(),
            size: None,
        };
        for line in [
            "MAIL FROM:<campaigns@acme.io>",
            "MAIL FROM: <campaigns@acme.io>",
            "mail from:<campaigns@acme.io>",
            "MAIL FROM:campaigns@acme.io",
            "MAIL FROM : <campaigns@acme.io>",
        ] {
            assert_eq!(parsed(line), expected, "failed for {line:?}");
        }
    }

    #[test]
    fn null_sender_is_accepted() {
        assert_eq!(
            parsed("MAIL FROM:<>"),
            Command::Mail {
                address: String::new(),
                size: None
            }
        );
    }

    #[test]
    fn mail_parameters_are_parsed() {
        assert_eq!(
            parsed("MAIL FROM:<a@b.io> SIZE=12345 BODY=8BITMIME"),
            Command::Mail {
                address: "a@b.io".into(),
                size: Some(12_345)
            }
        );

        let error = parse(b"MAIL FROM:<a@b.io> SIZE=big").unwrap_err();
        assert_eq!(error.code, 501);

        let error = parse(b"MAIL FROM:<a@b.io> WEIRD=1").unwrap_err();
        assert_eq!(error.code, 555);
    }

    #[test]
    fn malformed_mail_is_rejected() {
        assert!(parse(b"MAIL").is_err());
        assert!(parse(b"MAIL TO:<a@b.io>").is_err());
        assert!(parse(b"MAIL FROM:<a@b.io").is_err());
    }

    #[test]
    fn rcpt_to_parses_and_requires_an_address() {
        assert_eq!(
            parsed("RCPT TO:<lead@example.org>"),
            Command::Rcpt {
                address: "lead@example.org".into()
            }
        );
        assert_eq!(
            parsed("RCPT TO:<lead@example.org> NOTIFY=NEVER"),
            Command::Rcpt {
                address: "lead@example.org".into()
            }
        );
        assert!(parse(b"RCPT TO:<>").is_err());
        assert!(parse(b"RCPT").is_err());
    }

    #[test]
    fn source_routes_are_stripped() {
        assert_eq!(
            parsed("RCPT TO:<@relay.example:lead@example.org>"),
            Command::Rcpt {
                address: "lead@example.org".into()
            }
        );
    }

    #[test]
    fn auth_parses_with_and_without_an_initial_response() {
        assert_eq!(
            parsed("AUTH LOGIN"),
            Command::Auth {
                mechanism: "LOGIN".into(),
                initial: None
            }
        );
        assert_eq!(
            parsed("AUTH PLAIN AGFAYi5pbwBzZWNyZXQ="),
            Command::Auth {
                mechanism: "PLAIN".into(),
                initial: Some("AGFAYi5pbwBzZWNyZXQ=".into())
            }
        );
        assert!(parse(b"AUTH").is_err());
    }

    #[test]
    fn addresses_with_odd_local_parts_survive() {
        assert_eq!(
            parsed("RCPT TO:<\"quoted local\"@example.org>"),
            Command::Rcpt {
                address: "\"quoted local\"@example.org".into()
            }
        );
        assert_eq!(
            parsed("MAIL FROM:<bounce+tag=x@acme.io>"),
            Command::Mail {
                address: "bounce+tag=x@acme.io".into(),
                size: None
            }
        );
    }
}
