use super::{DatabaseKind, ph};

pub(super) use super::placeholders as text_placeholders;

pub(super) fn case_expression(kind: DatabaseKind, start: usize, count: usize) -> (String, usize) {
    let end = start + count * 2;
    let expression = (0..count)
        .map(|offset| {
            format!(
                "WHEN {} THEN {}",
                ph(kind, start + offset * 2),
                ph(kind, start + offset * 2 + 1)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    (expression, end)
}
