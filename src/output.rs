// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-or-later
//! Bounding tool output, so a listing of a large binary cannot flood the
//! client's context: listings are paged (`offset`/`limit`) and every result is
//! held under a byte ceiling, with what was left out reported.
//!
//! Rizin has no native pagination yet (rizinorg/rizin#6543, D1), so it still
//! produces the full listing and the slicing happens here.

use serde::de::{Deserializer as _, IgnoredAny, SeqAccess, Visitor};
use serde_json::{Value, json};

const ADDRESS_KEYS: &[&str] = &[
    "offset", "address", "vaddr", "paddr", "addr", "from", "to", "jump", "fail", "fcn_addr",
    "fcn_last", "baddr", "laddr", "entry", "ptr", "plt", "hvaddr", "hpaddr", "val",
];

/// The page of a listing to return.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    /// Index of the first item.
    pub offset: usize,
    /// Maximum number of items, if any.
    pub limit: Option<usize>,
}

impl Page {
    /// Everything, subject only to the byte ceiling.
    pub const ALL: Page = Page {
        offset: 0,
        limit: None,
    };
}

/// Size of `value` serialized compactly, as it is sent.
fn json_len(value: &Value) -> usize {
    serde_json::to_string(value).map_or(0, |s| s.len())
}

pub fn enrich_addresses(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                enrich_addresses(item);
            }
        }
        Value::Object(map) => {
            let is_page_meta = map.contains_key("returned") && map.contains_key("truncated");
            let mut additions = Vec::new();
            if !is_page_meta {
                for (k, v) in map.iter() {
                    if ADDRESS_KEYS.contains(&k.as_str())
                        && let Some(n) = v.as_u64()
                    {
                        let hex_key = format!("{k}_hex");
                        if !map.contains_key(&hex_key) {
                            additions.push((hex_key, Value::String(format!("0x{n:x}"))));
                        }
                    }
                }
            }
            for v in map.values_mut() {
                enrich_addresses(v);
            }
            for (k, v) in additions {
                map.insert(k, v);
            }
        }
        _ => {}
    }
}

pub fn compact_op(op: &mut Value) {
    if let Value::Object(map) = op {
        for noisy in [
            "bytes",
            "esil",
            "refptr",
            "reloc",
            "fcn_addr",
            "fcn_last",
            "fcn_addr_hex",
            "fcn_last_hex",
            "family",
            "type_num",
            "type2_num",
            "size",
        ] {
            map.remove(noisy);
        }
        if map.contains_key("disasm") {
            map.remove("opcode");
        }
    }
}

/// Return `page` of `items` as `{"items", "total", "offset", "returned",
/// "truncated"[, "next_offset"]}`, keeping the serialized items within
/// `max_bytes` (at least one item is kept, so paging always progresses).
pub fn paginate(items: Vec<Value>, page: Page, max_bytes: usize) -> Value {
    let total = items.len();
    let offset = page.offset.min(total);
    let mut returned = Vec::new();
    let mut size = 2; // the brackets
    for mut item in items.into_iter().skip(offset) {
        if page.limit.is_some_and(|l| returned.len() >= l) {
            break;
        }
        enrich_addresses(&mut item);
        let len = json_len(&item) + 1; // the separating comma
        if !returned.is_empty() && size + len > max_bytes {
            break;
        }
        size += len;
        returned.push(item);
    }
    let count = returned.len();
    let next = offset + count;
    let mut out = json!({
        "items": returned,
        "total": total,
        "offset": offset,
        "returned": count,
        "truncated": next < total,
    });
    if next < total {
        out["next_offset"] = json!(next);
    }
    out
}

pub fn paginate_json_str(raw: &str, page: Page, max_bytes: usize) -> Option<Value> {
    let trimmed = raw.trim();
    if !trimmed.starts_with('[') {
        return None;
    }

    struct PageVisitor {
        page: Page,
        max_bytes: usize,
    }

    impl<'de> Visitor<'de> for PageVisitor {
        type Value = (Vec<Value>, usize);

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a JSON array")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut total = 0usize;
            let mut returned = Vec::new();
            let mut size = 2usize;
            let mut full = false;

            while total < self.page.offset {
                if seq.next_element::<IgnoredAny>()?.is_none() {
                    return Ok((returned, total));
                }
                total += 1;
            }

            while !full {
                if self.page.limit.is_some_and(|l| returned.len() >= l) {
                    break;
                }
                let Some(mut item) = seq.next_element::<Value>()? else {
                    return Ok((returned, total));
                };
                total += 1;
                enrich_addresses(&mut item);
                let len = json_len(&item) + 1;
                if !returned.is_empty() && size + len > self.max_bytes {
                    full = true;
                } else {
                    size += len;
                    returned.push(item);
                }
            }

            while seq.next_element::<IgnoredAny>()?.is_some() {
                total += 1;
            }

            Ok((returned, total))
        }
    }

    let mut de = serde_json::Deserializer::from_str(trimmed);
    let (returned, total) = de
        .deserialize_seq(PageVisitor { page, max_bytes })
        .ok()?;
    if de.end().is_err() {
        return None;
    }

    let offset = page.offset.min(total);
    let count = returned.len();
    let next = offset + count;
    let mut out = json!({
        "items": returned,
        "total": total,
        "offset": offset,
        "returned": count,
        "truncated": next < total,
    });
    if next < total {
        out["next_offset"] = json!(next);
    }
    Some(out)
}

fn parse_afl_line(line: &str) -> Option<Value> {
    let mut parts = line.split_whitespace();
    let addr_str = parts.next()?;
    let hex = addr_str
        .strip_prefix("0x")
        .or_else(|| addr_str.strip_prefix("0X"))?;
    let offset = u64::from_str_radix(hex, 16).ok()?;
    let nbbs: u64 = parts.next()?.parse().ok()?;
    let size: u64 = parts.next()?.parse().ok()?;
    let name: String = parts.collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        return None;
    }
    Some(json!({
        "offset": offset,
        "offset_hex": format!("0x{offset:x}"),
        "name": name,
        "size": size,
        "nbbs": nbbs,
    }))
}

pub fn paginate_afl(text: &str, page: Page, max_bytes: usize) -> Value {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("0x") || l.starts_with("0X"))
        .collect();
    let total = lines.len();
    let offset = page.offset.min(total);
    let mut returned = Vec::new();
    let mut size = 2usize;

    for &line in lines.iter().skip(offset) {
        if page.limit.is_some_and(|l| returned.len() >= l) {
            break;
        }
        let Some(item) = parse_afl_line(line) else {
            continue;
        };
        let len = json_len(&item) + 1;
        if !returned.is_empty() && size + len > max_bytes {
            break;
        }
        size += len;
        returned.push(item);
    }

    let count = returned.len();
    let next = offset + count;
    let mut out = json!({
        "items": returned,
        "total": total,
        "offset": offset,
        "returned": count,
        "truncated": next < total,
    });
    if next < total {
        out["next_offset"] = json!(next);
    }
    out
}

/// Cut `text` to at most `max_bytes`, at a line end when there is one, and say
/// how much was left out. Returns the text and whether it was cut.
pub fn truncate_text(text: String, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    if let Some(nl) = text[..end].rfind('\n') {
        end = nl + 1;
    }
    let total = text.len();
    let mut cut = text;
    cut.truncate(end);
    if !cut.ends_with('\n') {
        cut.push('\n');
    }
    cut.push_str(&format!(
        "[output truncated: {end} of {total} bytes shown; narrow the request, \
         or raise the server's --max-output-bytes]\n"
    ));
    (cut, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn nums(n: usize) -> Vec<Value> {
        (0..n).map(|i| json!(i)).collect()
    }

    #[test]
    fn pages_through_a_listing() {
        let p = paginate(
            nums(10),
            Page {
                offset: 0,
                limit: Some(4),
            },
            1 << 20,
        );
        assert_eq!(p["items"], json!([0, 1, 2, 3]));
        assert_eq!(p["total"], 10);
        assert_eq!(p["truncated"], true);
        assert_eq!(p["next_offset"], 4);

        let last = paginate(
            nums(10),
            Page {
                offset: 8,
                limit: Some(4),
            },
            1 << 20,
        );
        assert_eq!(last["items"], json!([8, 9]));
        assert_eq!(last["truncated"], false);
        assert!(last.get("next_offset").is_none());

        let past = paginate(
            nums(3),
            Page {
                offset: 7,
                limit: None,
            },
            1 << 20,
        );
        assert_eq!(past["items"], json!([]));
        assert_eq!(past["offset"], 3);
    }

    #[test]
    fn byte_ceiling_cuts_but_always_progresses() {
        let big: Vec<Value> = (0..5).map(|i| json!("x".repeat(100 + i))).collect();
        let p = paginate(big.clone(), Page::ALL, 250);
        assert_eq!(p["returned"], 2);
        assert_eq!(p["next_offset"], 2);
        let one = paginate(big, Page::ALL, 10);
        assert_eq!(one["returned"], 1);
    }

    #[test]
    fn truncates_text_at_a_line_end() {
        let (t, cut) = truncate_text("aaa\nbbb\nccc\n".into(), 9);
        assert!(cut);
        assert!(t.starts_with("aaa\nbbb\n["), "{t:?}");
        assert!(t.contains("8 of 12 bytes"));
        let (t, cut) = truncate_text("short".into(), 9);
        assert_eq!((t.as_str(), cut), ("short", false));
        // A multi-byte character is never split.
        let (t, _) = truncate_text("ééééé".into(), 3);
        assert!(t.starts_with("é\n["), "{t:?}");
    }

    proptest! {
        // Pages tile the listing: following next_offset visits every item
        // exactly once, in order, whatever the limit and ceiling.
        #[test]
        fn pages_tile_the_listing(
            lens in proptest::collection::vec(0usize..50, 0..60),
            limit in proptest::option::of(1usize..10),
            max_bytes in 1usize..300,
        ) {
            let items: Vec<Value> = lens.iter().map(|&n| json!("y".repeat(n))).collect();
            let mut seen = Vec::new();
            let mut offset = 0;
            loop {
                let p = paginate(items.clone(), Page { offset, limit }, max_bytes);
                let got = p["items"].as_array().unwrap().clone();
                prop_assert_eq!(p["total"].as_u64(), Some(items.len() as u64));
                if let Some(l) = limit {
                    prop_assert!(got.len() <= l);
                }
                if got.len() > 1 {
                    prop_assert!(json_len(&p["items"]) <= max_bytes);
                }
                seen.extend(got);
                match p.get("next_offset").and_then(Value::as_u64) {
                    Some(next) => {
                        prop_assert!(next as usize > offset);
                        offset = next as usize;
                    }
                    None => break,
                }
            }
            prop_assert_eq!(seen, items);
        }

        // Cut text is a prefix of the original plus the notice.
        #[test]
        fn truncated_text_is_a_prefix(text in "\\PC{0,400}", max in 1usize..200) {
            let (t, cut) = truncate_text(text.clone(), max);
            if cut {
                let notice = t.rfind("[output truncated:").unwrap();
                let shown = &t[..notice];
                let shown = if text.starts_with(shown) {
                    shown
                } else {
                    // A newline was added before the notice.
                    shown.strip_suffix('\n').unwrap()
                };
                prop_assert!(text.starts_with(shown));
                prop_assert!(shown.len() <= max);
            } else {
                prop_assert_eq!(t, text);
            }
        }
    }
}
