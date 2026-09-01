use super::{AppResult, DatabaseKind};
use diesel::{
    Connection,
    backend::Backend,
    query_builder::{BoxedSqlQuery, SqlQuery},
    serialize::ToSql,
    sql_types::Text,
};

pub(super) async fn blocking<T>(f: impl FnOnce() -> AppResult<T> + Send + 'static) -> AppResult<T>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| super::AppError::Internal(err.to_string()))?
}

pub(super) fn ph(kind: DatabaseKind, index: usize) -> String {
    match kind {
        DatabaseKind::Postgres => format!("${index}"),
        DatabaseKind::Sqlite | DatabaseKind::Mysql => "?".to_string(),
    }
}

pub(super) fn placeholders(kind: DatabaseKind, start: usize, count: usize) -> String {
    let mut result = String::new();
    for index in start..start + count {
        if index > start {
            result.push_str(", ");
        }
        result.push_str(&ph(kind, index));
    }
    result
}

pub(super) fn placeholder_rows(
    kind: DatabaseKind,
    start: usize,
    row_count: usize,
    column_count: usize,
) -> String {
    (0..row_count)
        .map(|row| {
            format!(
                "({})",
                placeholders(kind, start + row * column_count, column_count)
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn bind_text_list<Conn>(
    _connection: &mut Conn,
    query: SqlQuery,
    values: &[String],
) -> BoxedSqlQuery<'static, Conn::Backend, SqlQuery>
where
    Conn: Connection,
    Conn::Backend: Backend + diesel::sql_types::HasSqlType<Text>,
    String: ToSql<Text, Conn::Backend> + Send + 'static,
{
    let mut query = query.into_boxed::<Conn::Backend>();
    for value in values {
        query = query.bind::<Text, _>(value.clone());
    }
    query
}
