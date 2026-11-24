// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One page of a listing, read from the object store's answer.
//!
//! The answer is XML, and the product carries no XML reader for five element names. This reads
//! exactly those, in the one shape the store answers them in, and refuses the page otherwise:
//! an answer it does not read whole is never a shorter listing.

/// One object of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// The key, whole.
    pub key: String,
    /// Its size at rest, in bytes.
    pub bytes: u64,
    /// When it was last written, seconds since the Unix epoch.
    pub modified: u64,
}

/// One page: its objects, and where the next page starts when there is one.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Page {
    pub objects: Vec<Listed>,
    pub next: Option<String>,
}

/// The text of the first element `name` of `xml`, entities resolved.
fn text(xml: &str, name: &str) -> Result<Option<String>, String> {
    let (open, close) = (format!("<{name}>"), format!("</{name}>"));
    let Some(start) = xml.find(&open) else {
        return Ok(None);
    };
    let rest = &xml[start + open.len()..];
    let end = rest
        .find(&close)
        .ok_or_else(|| format!("the element {name} of a listing does not end"))?;
    unescape(&rest[..end]).map(Some)
}

fn unescape(text: &str) -> Result<String, String> {
    if text.contains('<') {
        return Err("an element of a listing holds another where text was expected".to_owned());
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let entity = &rest[at..];
        let end = entity
            .find(';')
            .ok_or_else(|| "an entity of a listing does not end".to_owned())?;
        out.push(match &entity[1..end] {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            other => {
                let code = other
                    .strip_prefix("#x")
                    .map(|hex| u32::from_str_radix(hex, 16))
                    .or_else(|| other.strip_prefix('#').map(str::parse))
                    .and_then(Result::ok)
                    .and_then(char::from_u32);
                code.ok_or_else(|| format!("a listing holds the entity `{other}`"))?
            }
        });
        rest = &entity[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Reads one page of a `ListObjectsV2` answer.
pub(crate) fn page(xml: &str) -> Result<Page, String> {
    if !xml.contains("<ListBucketResult") {
        return Err("the answer is no listing".to_owned());
    }
    let mut objects = Vec::new();
    // What is outside the objects says whether the listing goes on, and from where.
    let mut outside = String::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Contents>") {
        outside.push_str(&rest[..start]);
        let inside = &rest[start + "<Contents>".len()..];
        let end = inside
            .find("</Contents>")
            .ok_or_else(|| "an object of a listing does not end".to_owned())?;
        let object = &inside[..end];
        let field = |name: &str| {
            text(object, name)?.ok_or_else(|| format!("an object of a listing has no {name}"))
        };
        let modified = field("LastModified")?;
        objects.push(Listed {
            key: field("Key")?,
            bytes: field("Size")?
                .parse()
                .map_err(|_| "an object of a listing has a size that is no number".to_owned())?,
            modified: permguard_core::time::from_rfc3339(&modified)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .ok_or_else(|| format!("an object of a listing was written at `{modified}`"))?,
        });
        rest = &inside[end + "</Contents>".len()..];
    }
    outside.push_str(rest);
    let next = match text(&outside, "IsTruncated")?.as_deref() {
        Some("true") => Some(
            text(&outside, "NextContinuationToken")?
                .ok_or_else(|| "a listing goes on and does not say from where".to_owned())?,
        ),
        Some("false") | None => None,
        Some(other) => return Err(format!("a listing says it is truncated `{other}`")),
    };
    Ok(Page { objects, next })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_page_is_read_whole() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix>p/</Prefix>
<KeyCount>2</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>true</IsTruncated>
<Contents><Key>p/a&amp;b</Key><LastModified>2026-11-22T11:23:00.000Z</LastModified><ETag>&quot;x&quot;</ETag><Size>4</Size><StorageClass>STANDARD</StorageClass></Contents>
<Contents><Key>p/c</Key><LastModified>2026-11-22T11:23:01Z</LastModified><Size>0</Size></Contents>
<NextContinuationToken>t+1=</NextContinuationToken></ListBucketResult>"#;
        let page = page(xml).expect("a page");
        assert_eq!(
            page.objects,
            vec![
                Listed {
                    key: "p/a&b".to_owned(),
                    bytes: 4,
                    modified: 1_795_346_580,
                },
                Listed {
                    key: "p/c".to_owned(),
                    bytes: 0,
                    modified: 1_795_346_581,
                },
            ]
        );
        assert_eq!(page.next.as_deref(), Some("t+1="));
    }

    #[test]
    fn an_empty_listing_is_a_page_with_nothing() {
        let page = page("<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>")
            .expect("a page");
        assert!(page.objects.is_empty());
        assert_eq!(page.next, None);
    }

    #[test]
    fn an_answer_that_does_not_read_whole_is_refused() {
        for xml in [
            "<Error><Code>AccessDenied</Code></Error>",
            "<ListBucketResult><Contents><Key>a</Key><Size>1</Size></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>a</Key><Size>x</Size><LastModified>2026-11-22T11:23:00Z</LastModified></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>a</Key>",
            "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
            "<ListBucketResult><Contents><Key>a&bogus;</Key><Size>1</Size><LastModified>2026-11-22T11:23:00Z</LastModified></Contents></ListBucketResult>",
        ] {
            assert!(page(xml).is_err(), "{xml}");
        }
    }
}
