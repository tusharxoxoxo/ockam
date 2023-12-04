use ockam::identity::TimestampInSeconds;
use sqlx::*;
use tracing::debug;

use ockam_core::async_trait;
use ockam_core::compat::sync::Arc;
use ockam_core::Result;
use ockam_node::database::{FromSqlxError, SqlxDatabase, ToSqlxType, ToVoid};

use crate::authenticator::one_time_code::OneTimeCode;
use crate::authenticator::{AuthorityEnrollmentTokensRepository, Token, TokenRow};

/// Implementation of `IdentitiesRepository` trait based on an underlying database
/// using sqlx as its API, and Sqlite as its driver
#[derive(Clone)]
pub struct AuthorityEnrollmentTokensSqlxDatabase {
    database: Arc<SqlxDatabase>,
}

impl AuthorityEnrollmentTokensSqlxDatabase {
    /// Create a new database
    pub fn new(database: Arc<SqlxDatabase>) -> Self {
        debug!("create a repository for change history");
        Self { database }
    }

    /// Create a new in-memory database
    pub async fn create() -> Result<Arc<Self>> {
        Ok(Arc::new(Self::new(
            SqlxDatabase::in_memory("change history").await?,
        )))
    }
}

#[async_trait]
impl AuthorityEnrollmentTokensRepository for AuthorityEnrollmentTokensSqlxDatabase {
    async fn use_token(
        &self,
        one_time_code: OneTimeCode,
        now: TimestampInSeconds,
    ) -> Result<Option<Token>> {
        let query1 =
            query("DELETE FROM authority_enrollment_token WHERE expires_at<=?").bind(now.to_sql());

        query1.execute(&self.database.pool).await.void()?;

        let mut transaction = self.database.pool.begin().await.into_core()?;

        let query2 = query_as("SELECT one_time_code, issued_by, created_at, expires_at, ttl_count, attributes FROM authority_enrollment_token WHERE one_time_code=?")
            .bind(one_time_code.to_sql());
        let row: Option<TokenRow> = query2.fetch_optional(&mut *transaction).await.into_core()?;
        let token: Option<Token> = row.map(|r| r.try_into()).transpose()?;

        if let Some(token) = &token {
            if token.ttl_count <= 1 {
                let query3 = query("DElETE FROM authority_enrollment_token WHERE one_time_code=?")
                    .bind(one_time_code.to_sql());
                query3.execute(&mut *transaction).await.void()?;
            } else {
                let query3 = query(
                    "UPDATE authority_enrollment_token SET ttl_count=? WHERE one_time_code=?",
                )
                .bind((token.ttl_count - 1) as i64)
                .bind(one_time_code.to_sql());
                query3.execute(&mut *transaction).await.void()?;
            }
        }

        transaction.commit().await.void()?;

        Ok(token)
    }

    async fn issue_token(&self, token: Token) -> Result<()> {
        let query = query(
            "INSERT OR REPLACE INTO authority_enrollment_token VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(token.one_time_code.to_sql())
        .bind(token.issued_by.to_sql())
        .bind(token.created_at.to_sql())
        .bind(token.expires_at.to_sql())
        .bind(token.ttl_count.to_sql())
        .bind(minicbor::to_vec(token.attrs)?.to_sql());

        query.execute(&self.database.pool).await.void()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ockam::identity::utils::now;
    use ockam::identity::Identifier;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::time::Duration;

    #[tokio::test]
    async fn test_authority_enrollment_token_repository_one_time_token() -> Result<()> {
        let repository = create_repository().await?;

        let one_time_code = OneTimeCode::new();

        let issued_by = Identifier::from_str(
            "I0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        let created_at = now()?;
        let expires_at = created_at + 10;

        let mut attrs = HashMap::<String, String>::default();
        attrs.insert("role".to_string(), "user".to_string());

        let token = Token {
            one_time_code: one_time_code.clone(),
            issued_by: issued_by.clone(),
            created_at,
            expires_at,
            ttl_count: 1,
            attrs: attrs.clone(),
        };

        repository.issue_token(token).await?;

        let token1 = repository.use_token(one_time_code.clone(), now()?).await?;
        assert!(token1.is_some());
        let token1 = token1.unwrap();
        assert_eq!(token1.one_time_code, one_time_code);
        assert_eq!(token1.issued_by, issued_by);
        assert_eq!(token1.created_at, created_at);
        assert_eq!(token1.expires_at, expires_at);
        assert_eq!(token1.ttl_count, 1);
        assert_eq!(token1.attrs, attrs);

        let token2 = repository.use_token(one_time_code, now()?).await?;
        assert!(token2.is_none());

        Ok(())
    }

    #[tokio::test]
    async fn test_authority_enrollment_token_repository_two_time_token() -> Result<()> {
        let repository = create_repository().await?;

        let one_time_code = OneTimeCode::new();

        let issued_by = Identifier::from_str(
            "I0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        let created_at = now()?;
        let expires_at = created_at + 10;

        let mut attrs = HashMap::<String, String>::default();
        attrs.insert("role".to_string(), "user".to_string());

        let token = Token {
            one_time_code: one_time_code.clone(),
            issued_by: issued_by.clone(),
            created_at,
            expires_at,
            ttl_count: 2,
            attrs: attrs.clone(),
        };

        repository.issue_token(token).await?;

        let token1 = repository.use_token(one_time_code.clone(), now()?).await?;
        let token2 = repository.use_token(one_time_code.clone(), now()?).await?;
        let token3 = repository.use_token(one_time_code.clone(), now()?).await?;
        assert!(token1.is_some());
        assert!(token2.is_some());
        assert!(token3.is_none());

        let token1 = token1.unwrap();
        let token2 = token2.unwrap();

        assert_eq!(token1.one_time_code, token2.one_time_code);
        assert_eq!(token1.issued_by, token2.issued_by);
        assert_eq!(token1.created_at, token2.created_at);
        assert_eq!(token1.expires_at, token2.expires_at);
        assert_eq!(token1.attrs, token2.attrs);

        assert_eq!(token1.ttl_count, 2);
        assert_eq!(token2.ttl_count, 1);

        Ok(())
    }

    #[tokio::test]
    async fn test_authority_enrollment_token_repository_expired_token() -> Result<()> {
        let repository = create_repository().await?;

        let one_time_code = OneTimeCode::new();

        let issued_by = Identifier::from_str(
            "I0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        let created_at = now()?;
        let expires_at = created_at + 1;

        let mut attrs = HashMap::<String, String>::default();
        attrs.insert("role".to_string(), "user".to_string());

        let token = Token {
            one_time_code: one_time_code.clone(),
            issued_by: issued_by.clone(),
            created_at,
            expires_at,
            ttl_count: 1,
            attrs: attrs.clone(),
        };

        repository.issue_token(token).await?;

        tokio::time::sleep(Duration::from_secs(2)).await;

        let token1 = repository.use_token(one_time_code.clone(), now()?).await?;
        assert!(token1.is_none());

        Ok(())
    }

    /// HELPERS
    async fn create_repository() -> Result<Arc<dyn AuthorityEnrollmentTokensRepository>> {
        Ok(AuthorityEnrollmentTokensSqlxDatabase::create().await?)
    }
}
