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
