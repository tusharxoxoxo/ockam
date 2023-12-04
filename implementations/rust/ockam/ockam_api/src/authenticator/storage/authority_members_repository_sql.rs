use sqlx::*;
use tracing::debug;

use ockam::identity::{Identifier, TimestampInSeconds};
use ockam_core::async_trait;
use ockam_core::compat::sync::Arc;
use ockam_core::Result;
use ockam_node::database::{FromSqlxError, SqlxDatabase, ToSqlxType, ToVoid};

use crate::authenticator::{
    AuthorityMember, AuthorityMemberRow, AuthorityMembersRepository, PreTrustedIdentities,
};

#[derive(Clone)]
pub struct AuthorityMembersSqlxDatabase {
    database: Arc<SqlxDatabase>,
}

impl AuthorityMembersSqlxDatabase {
    /// Create a new database
    pub fn new(database: Arc<SqlxDatabase>) -> Self {
        debug!("create a repository for authority members history");
        Self { database }
    }

    /// Create a new in-memory database
    pub async fn create() -> Result<Arc<Self>> {
        Ok(Arc::new(Self::new(
            SqlxDatabase::in_memory("authority members").await?,
        )))
    }
}

// FIXME: Handle expirations
#[async_trait]
impl AuthorityMembersRepository for AuthorityMembersSqlxDatabase {
    async fn get_member(&self, identifier: &Identifier) -> Result<Option<AuthorityMember>> {
        let query = query_as("SELECT identifier, attributes, added_by, added_at, expires_at, is_pre_trusted FROM authority_member WHERE identifier=?")
            .bind(identifier.to_sql());
        let row: Option<AuthorityMemberRow> = query
            .fetch_optional(&self.database.pool)
            .await
            .into_core()?;
        row.map(|r| r.try_into()).transpose()
    }

    async fn get_members(&self) -> Result<Vec<AuthorityMember>> {
        let query = query_as("SELECT identifier, attributes, added_by, added_at, expires_at, is_pre_trusted FROM authority_member");
        let row: Vec<AuthorityMemberRow> =
            query.fetch_all(&self.database.pool).await.into_core()?;
        row.into_iter().map(|r| r.try_into()).collect()
    }

    async fn delete_member(&self, identifier: &Identifier) -> Result<()> {
        let query = query("DELETE FROM authority_member WHERE identifier=? AND is_pre_trusted=?")
            .bind(identifier.to_sql())
            .bind(false.to_sql());
        query.execute(&self.database.pool).await.void()
    }

    async fn add_member(&self, member: AuthorityMember) -> Result<()> {
        let query =
            query("INSERT OR REPLACE INTO authority_member VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
                .bind(member.identifier().to_sql())
                .bind(member.added_by().clone().map(|x| x.to_sql()))
                .bind(member.added_at().to_sql())
                .bind(member.expires_at().map(|x| x.to_sql()))
                .bind(member.is_pre_trusted().to_sql())
                .bind(minicbor::to_vec(member.attributes())?.to_sql());

        query.execute(&self.database.pool).await.void()
    }

    async fn bootstrap_pre_trusted_members(
        &self,
        pre_trusted_identities: &PreTrustedIdentities,
    ) -> Result<()> {
        let mut transaction = self.database.begin().await.into_core()?;
        let query1 =
            query("DELETE FROM authority_member WHERE is_pre_trusted=?").bind(true.to_sql());
        query1.execute(&mut *transaction).await.void()?;

        for (identifier, attributes_entry) in &pre_trusted_identities.0 {
            let query2 =
                query("INSERT OR REPLACE INTO authority_member VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
                    .bind(identifier.to_sql())
                    .bind(attributes_entry.attested_by().map(|x| x.to_sql()))
                    .bind(attributes_entry.added().to_sql())
                    .bind((None as Option<TimestampInSeconds>).map(|x| x.to_sql()))
                    .bind(true.to_sql())
                    .bind(minicbor::to_vec(attributes_entry.attrs())?.to_sql());

            query2.execute(&mut *transaction).await.void()?;
        }

        transaction.commit().await.void()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ockam::identity::models::IDENTIFIER_LEN;
    use ockam::identity::utils::now;
    use ockam::identity::{AttributesEntry, Identifier};
    use ockam_core::compat::collections::HashMap;
    use ockam_core::compat::rand::RngCore;
    use rand::thread_rng;
    use std::collections::BTreeMap;

    fn random_identifier() -> Identifier {
        let mut data = [0u8; IDENTIFIER_LEN];

        let mut rng = thread_rng();
        rng.fill_bytes(&mut data);

        Identifier(data)
    }

    #[tokio::test]
    async fn test_authority_members_repository_crud() -> Result<()> {
        let repository = create_repository().await?;

        let admin = random_identifier();
        let timestamp1 = now()?;

        let identifier1 = random_identifier();
        let mut attributes1 = BTreeMap::<Vec<u8>, Vec<u8>>::default();
        attributes1.insert("role".as_bytes().to_vec(), "enroller".as_bytes().to_vec());
        let member1 = AuthorityMember::new(
            identifier1.clone(),
            attributes1,
            Some(admin.clone()),
            timestamp1,
            None,
            false,
        );
        repository.add_member(member1.clone()).await?;

        let members = repository.get_members().await?;
        assert_eq!(members.len(), 1);
        assert!(members.contains(&member1));

        let identifier2 = random_identifier();
        let mut attributes2 = BTreeMap::<Vec<u8>, Vec<u8>>::default();
        attributes2.insert("role".as_bytes().to_vec(), "user".as_bytes().to_vec());
        let timestamp2 = timestamp1 + 10;
        let member2 = AuthorityMember::new(
            identifier2.clone(),
            attributes2,
            None,
            timestamp2,
            None,
            false,
        );
        repository.add_member(member2.clone()).await?;

        let members = repository.get_members().await?;
        assert_eq!(members.len(), 2);
        assert!(members.contains(&member1));
        assert!(members.contains(&member2));

        repository.delete_member(&identifier1).await?;

        let members = repository.get_members().await?;
        assert_eq!(members.len(), 1);
        assert!(members.contains(&member2));

        Ok(())
    }

    #[tokio::test]
    async fn test_authority_members_repository_bootstrap() -> Result<()> {
        let repository = create_repository().await?;

        let mut pre_trusted_identities = HashMap::<Identifier, AttributesEntry>::default();

        let timestamp1 = now()?;

        let identifier1 = random_identifier();
        let mut attributes1 = BTreeMap::<Vec<u8>, Vec<u8>>::default();
        attributes1.insert("role".as_bytes().to_vec(), "enroller".as_bytes().to_vec());

        pre_trusted_identities.insert(
            identifier1.clone(),
            AttributesEntry::new(attributes1.clone(), timestamp1, None, None),
        );

        let identifier2 = random_identifier();
        let mut attributes2 = BTreeMap::<Vec<u8>, Vec<u8>>::default();
        attributes2.insert("role".as_bytes().to_vec(), "user".as_bytes().to_vec());
        let timestamp2 = timestamp1 + 10;
        let timestamp3 = timestamp2 + 10;

        pre_trusted_identities.insert(
            identifier2.clone(),
            AttributesEntry::new(
                attributes2.clone(),
                timestamp2,
                Some(timestamp3),
                Some(identifier1.clone()),
            ),
        );

        let pre_trusted_identities = PreTrustedIdentities::new_from_hashmap(pre_trusted_identities);

        repository
            .bootstrap_pre_trusted_members(&pre_trusted_identities)
            .await?;

        let members = repository.get_members().await?;
        assert_eq!(members.len(), 2);
        let member1 = members
            .iter()
            .find(|x| x.identifier() == &identifier1)
            .unwrap();
        assert_eq!(member1.added_at(), timestamp1);
        assert_eq!(member1.added_by(), &None);
        assert_eq!(member1.attributes(), &attributes1);
        assert!(member1.is_pre_trusted());

        let member2 = members
            .iter()
            .find(|x| x.identifier() == &identifier2)
            .unwrap();
        assert_eq!(member2.added_at(), timestamp2);
        assert_eq!(member2.added_by(), &Some(identifier1));
        assert_eq!(member2.attributes(), &attributes2);
        assert!(member2.is_pre_trusted());

        //
        // repository.delete_member(&identifier1).await?;
        //
        // let members = repository.get_members().await?;
        // assert_eq!(members.len(), 1);
        // assert!(members.contains(&member2));

        Ok(())
    }

    /// HELPERS
    async fn create_repository() -> Result<Arc<dyn AuthorityMembersRepository>> {
        Ok(AuthorityMembersSqlxDatabase::create().await?)
    }
}
