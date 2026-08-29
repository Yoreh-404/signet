use super::{DatabaseKind, ph};

pub(super) fn text_placeholders(kind: DatabaseKind, start: usize, count: usize) -> String {
    (start..start + count)
        .map(|index| ph(kind, index))
        .collect::<Vec<_>>()
        .join(", ")
}

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
