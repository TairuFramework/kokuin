//! The few JavaScript value semantics the fold leans on when it reads wire data: property access,
//! `ToNumber` for a relational comparison, `String(value)`, truthiness and strict equality with a
//! number. The fold's input is `JSON.parse` output, so a field may hold any JSON type, and TS reads
//! it with these rules rather than rejecting it.

use serde_json::Value;
use sozai_codec::canonical::format_number;

/// `value[key]` for a JSON value: only an object has named properties here. An array's are its
/// indices and `length`, which the fold never reads.
pub(crate) fn prop<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map.get(key),
        _ => None,
    }
}

/// `prop(value, key) === text`.
pub(crate) fn prop_is(value: &Value, key: &str, text: &str) -> bool {
    prop(value, key).and_then(Value::as_str) == Some(text)
}

/// `value === number`, where absent is `undefined`.
pub(crate) fn strict_eq_number(value: Option<&Value>, number: f64) -> bool {
    value.and_then(Value::as_f64) == Some(number)
}

/// `Number.isSafeInteger(value)`.
pub(crate) fn is_safe_integer(value: Option<&Value>) -> bool {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    value
        .and_then(Value::as_f64)
        .is_some_and(|number| number.trunc() == number && number.abs() <= MAX_SAFE_INTEGER)
}

/// Truthiness, where absent is `undefined`.
pub(crate) fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|number| number != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

/// JavaScript's `Number#toString` for a finite number.
pub(crate) fn number_string(number: f64) -> String {
    format_number(number).unwrap_or_else(|_| {
        if number.is_nan() {
            "NaN".into()
        } else if number > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    })
}

/// `String(value)`, where absent is `undefined`.
pub(crate) fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Number(number)) => number_string(number.as_f64().unwrap_or(f64::NAN)),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

/// `ToNumber(ToPrimitive(value))`, as a relational comparison against a number applies it.
pub(crate) fn to_number(value: Option<&Value>) -> f64 {
    match value {
        None | Some(Value::Object(_)) => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(flag)) => f64::from(u8::from(*flag)),
        Some(Value::Number(number)) => number.as_f64().unwrap_or(f64::NAN),
        Some(Value::String(text)) => string_to_number(text),
        Some(array @ Value::Array(_)) => string_to_number(&js_string(Some(array))),
    }
}

/// JavaScript `WhiteSpace` and `LineTerminator`: Unicode `White_Space` minus U+0085, plus U+FEFF.
fn is_js_space(c: char) -> bool {
    c == '\u{feff}' || (c.is_whitespace() && c != '\u{85}')
}

fn radix_to_number(digits: &str, radix: u32) -> f64 {
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return f64::NAN;
    }
    if let Ok(value) = u128::from_str_radix(digits, radix) {
        return value as f64;
    }
    digits.chars().fold(0.0, |total, c| {
        total * f64::from(radix) + f64::from(c.to_digit(radix).unwrap_or(0))
    })
}

fn is_decimal_literal(text: &str) -> bool {
    let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(index) => (&unsigned[..index], Some(&unsigned[index + 1..])),
        None => (unsigned, None),
    };
    let digits = |part: &str| part.chars().all(|c| c.is_ascii_digit());
    let mantissa_ok = match mantissa.split_once('.') {
        Some((whole, fraction)) => {
            !(whole.is_empty() && fraction.is_empty()) && digits(whole) && digits(fraction)
        }
        None => !mantissa.is_empty() && digits(mantissa),
    };
    let exponent_ok = exponent.is_none_or(|exponent| {
        let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        !exponent.is_empty() && digits(exponent)
    });
    mantissa_ok && exponent_ok
}

/// `StringToNumber`.
fn string_to_number(text: &str) -> f64 {
    let text = text.trim_matches(is_js_space);
    if text.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            return radix_to_number(digits, radix);
        }
    }
    match text {
        "Infinity" | "+Infinity" => return f64::INFINITY,
        "-Infinity" => return f64::NEG_INFINITY,
        _ => {}
    }
    if !is_decimal_literal(text) {
        return f64::NAN;
    }
    text.parse::<f64>().unwrap_or(f64::NAN)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn to_number_follows_javascript() {
        let cases = [
            (json!(null), 0.0),
            (json!(true), 1.0),
            (json!(" 12 "), 12.0),
            (json!(""), 0.0),
            (json!("0x10"), 16.0),
            (json!("1e3"), 1000.0),
            (json!(".5"), 0.5),
            (json!("5."), 5.0),
            (json!([7]), 7.0),
            (json!([]), 0.0),
            (json!("-Infinity"), f64::NEG_INFINITY),
        ];
        for (value, expected) in cases {
            assert_eq!(to_number(Some(&value)), expected, "{value}");
        }
        for value in [
            json!("inf"),
            json!("nan"),
            json!("1_0"),
            json!([1, 2]),
            json!({}),
        ] {
            assert!(to_number(Some(&value)).is_nan(), "{value}");
        }
        assert!(to_number(None).is_nan());
    }

    #[test]
    fn string_follows_javascript() {
        assert_eq!(js_string(None), "undefined");
        assert_eq!(js_string(Some(&json!([1, null, [2, "a"]]))), "1,,2,a");
        assert_eq!(js_string(Some(&json!({"a": 1}))), "[object Object]");
        assert_eq!(js_string(Some(&json!(1e21))), "1e+21");
    }
}
