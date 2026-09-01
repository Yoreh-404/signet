use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(super) struct UserLifecycleBatchInput {
    pub(super) action: String,
    pub(super) user_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct UserInput {
    pub(super) email: String,
    pub(super) username: String,
    pub(super) display_name: Option<String>,
    pub(super) phone: Option<String>,
    pub(super) password: Option<String>,
    pub(super) is_admin: bool,
    pub(super) is_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UserLifecycleMutation {
    PermanentlyDelete,
    Disable,
    Archive,
}

impl UserLifecycleMutation {
    pub(super) const fn action(self) -> &'static str {
        match self {
            Self::PermanentlyDelete => "deleted",
            Self::Disable => "disabled",
            Self::Archive => "archived",
        }
    }
}

pub(super) const fn lifecycle_mutation_for_user(
    archived_at: Option<i64>,
    is_active: i32,
) -> UserLifecycleMutation {
    if archived_at.is_some() {
        UserLifecycleMutation::PermanentlyDelete
    } else if is_active == 1 {
        UserLifecycleMutation::Disable
    } else {
        UserLifecycleMutation::Archive
    }
}

#[cfg(test)]
mod tests {
    use super::{UserLifecycleMutation, lifecycle_mutation_for_user};

    #[test]
    fn lifecycle_mutation_matches_account_state() {
        assert_eq!(
            lifecycle_mutation_for_user(None, 1),
            UserLifecycleMutation::Disable
        );
        assert_eq!(
            lifecycle_mutation_for_user(None, 0),
            UserLifecycleMutation::Archive
        );
        assert_eq!(
            lifecycle_mutation_for_user(Some(1), 0),
            UserLifecycleMutation::PermanentlyDelete
        );
    }
}
