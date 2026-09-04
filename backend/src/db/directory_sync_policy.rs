use super::DirectorySyncSnapshotPlan;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DirectorySyncPolicyError {
    DuplicateUserSubject,
    DuplicateUserDn,
    SubjectDnCollision,
    DuplicateEmail,
    DuplicateUsername,
    DuplicateGroupExternalId,
}

pub(super) fn validate_snapshot(
    snapshot: &DirectorySyncSnapshotPlan,
) -> Result<(), DirectorySyncPolicyError> {
    let mut subjects = BTreeSet::new();
    let mut dns = BTreeSet::new();
    let mut subject_owners = BTreeMap::new();
    let mut dn_owners = BTreeMap::new();
    let mut emails = BTreeSet::new();
    let mut usernames = BTreeSet::new();

    for (user_index, user) in snapshot.users.iter().enumerate() {
        if !subjects.insert(&user.subject) {
            return Err(DirectorySyncPolicyError::DuplicateUserSubject);
        }
        if !dns.insert(&user.dn) {
            return Err(DirectorySyncPolicyError::DuplicateUserDn);
        }
        if !emails.insert(&user.email) {
            return Err(DirectorySyncPolicyError::DuplicateEmail);
        }
        if !usernames.insert(&user.username) {
            return Err(DirectorySyncPolicyError::DuplicateUsername);
        }
        subject_owners.insert(user.subject.as_str(), user_index);
        dn_owners.insert(user.dn.as_str(), user_index);
    }

    if subject_owners.iter().any(|(key, subject_owner)| {
        dn_owners
            .get(key)
            .is_some_and(|dn_owner| dn_owner != subject_owner)
    }) {
        return Err(DirectorySyncPolicyError::SubjectDnCollision);
    }

    let mut group_external_ids = BTreeSet::new();
    for group in &snapshot.groups {
        if !group_external_ids.insert(&group.external_id) {
            return Err(DirectorySyncPolicyError::DuplicateGroupExternalId);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{DirectorySyncGroupPlan, DirectorySyncUserPlan};

    fn user(subject: &str, dn: &str, email: &str, username: &str) -> DirectorySyncUserPlan {
        DirectorySyncUserPlan {
            subject: subject.to_string(),
            dn: dn.to_string(),
            email: email.to_string(),
            username: username.to_string(),
            display_name: None,
            phone: None,
            password_hash: None,
        }
    }

    fn snapshot(users: Vec<DirectorySyncUserPlan>) -> DirectorySyncSnapshotPlan {
        DirectorySyncSnapshotPlan {
            users,
            groups: Vec::<DirectorySyncGroupPlan>::new(),
        }
    }

    #[test]
    fn accepts_distinct_subject_dns_and_identity_keys() {
        let plan = snapshot(vec![user(
            "subject-a",
            "uid=a,ou=people",
            "a@example.test",
            "a",
        )]);

        assert_eq!(validate_snapshot(&plan), Ok(()));
    }

    #[test]
    fn rejects_duplicate_subject() {
        let plan = snapshot(vec![
            user("same", "uid=a,ou=people", "a@example.test", "a"),
            user("same", "uid=b,ou=people", "b@example.test", "b"),
        ]);

        assert_eq!(
            validate_snapshot(&plan),
            Err(DirectorySyncPolicyError::DuplicateUserSubject)
        );
    }

    #[test]
    fn rejects_duplicate_dn() {
        let plan = snapshot(vec![
            user("a", "same-dn", "a@example.test", "a"),
            user("b", "same-dn", "b@example.test", "b"),
        ]);

        assert_eq!(
            validate_snapshot(&plan),
            Err(DirectorySyncPolicyError::DuplicateUserDn)
        );
    }

    #[test]
    fn rejects_subject_dn_collision_between_users() {
        let plan = snapshot(vec![
            user("shared-key", "uid=a,ou=people", "a@example.test", "a"),
            user("b", "shared-key", "b@example.test", "b"),
        ]);

        assert_eq!(
            validate_snapshot(&plan),
            Err(DirectorySyncPolicyError::SubjectDnCollision)
        );
    }

    #[test]
    fn allows_a_users_subject_to_equal_its_own_dn() {
        let plan = snapshot(vec![user(
            "shared-key",
            "shared-key",
            "a@example.test",
            "a",
        )]);

        assert_eq!(validate_snapshot(&plan), Ok(()));
    }

    #[test]
    fn rejects_duplicate_identity_keys() {
        let duplicate_email = snapshot(vec![
            user("a", "uid=a", "same@example.test", "a"),
            user("b", "uid=b", "same@example.test", "b"),
        ]);
        let duplicate_username = snapshot(vec![
            user("a", "uid=a", "a@example.test", "same"),
            user("b", "uid=b", "b@example.test", "same"),
        ]);

        assert_eq!(
            validate_snapshot(&duplicate_email),
            Err(DirectorySyncPolicyError::DuplicateEmail)
        );
        assert_eq!(
            validate_snapshot(&duplicate_username),
            Err(DirectorySyncPolicyError::DuplicateUsername)
        );
    }

    #[test]
    fn rejects_duplicate_group_external_id() {
        let mut plan = snapshot(Vec::new());
        plan.groups = vec![
            DirectorySyncGroupPlan {
                external_id: "same-group".to_string(),
                display_name: "First".to_string(),
                member_subjects: Vec::new(),
            },
            DirectorySyncGroupPlan {
                external_id: "same-group".to_string(),
                display_name: "Second".to_string(),
                member_subjects: Vec::new(),
            },
        ];

        assert_eq!(
            validate_snapshot(&plan),
            Err(DirectorySyncPolicyError::DuplicateGroupExternalId)
        );
    }
}
