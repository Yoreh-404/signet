import type { ChangeEvent, FormEvent } from "react";

import type { TranslationKey } from "../../i18n";
import type { BulkUserImportResult, Locale, OrganizationOption, User, UserDetail } from "../../types";
import { BulkUserImportModal } from "./BulkUserImportModal";
import type { BulkUserImportFormState } from "./BulkUserImportModal";
import { UserDirectoryPanel } from "./UserDirectoryPanel";
import type { UserDirectoryFilterState } from "./use-user-directory-query";
import { UserEditorModal } from "./UserEditorModal";
import type { UserEditorForm } from "./UserEditorModal";
import type { BulkUserAction } from "./user-lifecycle";

export type AdminUsersWorkspaceProps = {
  state: {
    editor: string | null;
    userForm: UserEditorForm;
    userFormDirty: boolean;
    error: string;
    bulkImportOpen: boolean;
    bulkImportCsv: string;
    bulkImportFileName: string;
    bulkImportDryRun: boolean;
    bulkImportCommitConfirmed: boolean;
    bulkImportResult: BulkUserImportResult | null;
    bulkImportError: string;
    users: User[];
    currentUserId?: string;
    selectedUserIdSet: ReadonlySet<string>;
    allVisibleUsersSelected: boolean;
    selectedUserCount: number;
    availableBulkUserActions: readonly BulkUserAction[];
    userDirectoryFilters: UserDirectoryFilterState;
    userFiltersExpanded: boolean;
    organizationOptions: OrganizationOption[];
    activeUserDirectoryPage: number;
    userPageStart: number;
    userPageEnd: number;
    adminViewLoading: boolean;
    hasNextUserDirectoryPage: boolean;
    searchQuery: string;
    selectedUser: UserDetail | null;
  };
  actions: {
    setUserForm: (form: UserEditorForm) => void;
    saveUser: (event: FormEvent<HTMLFormElement>) => void;
    closeEditor: () => void;
    closeBulkUserImport: () => void;
    submitBulkUserImport: (event: FormEvent<HTMLFormElement>) => void | Promise<void>;
    readBulkUserImportFile: (event: ChangeEvent<HTMLInputElement>) => void | Promise<void>;
    setBulkImportCsv: (value: string) => void;
    useBulkImportTemplate: () => void;
    setBulkImportDryRun: (value: boolean) => void;
    setBulkImportCommitConfirmed: (value: boolean) => void;
    resetBulkUserImport: () => void;
    toggleVisibleUserSelection: (checked: boolean) => void;
    toggleUserSelection: (id: string) => void;
    editUser: (user: User) => void;
    showUserDetails: (id: string) => void | Promise<void>;
    resetUserMfa: (id: string) => void | Promise<void>;
    advanceUserLifecycle: (id: string) => void | Promise<void>;
    enableUser: (id: string) => void | Promise<void>;
    requestConfirmation: (action: () => void | Promise<void>) => void;
    updateUserDirectoryFilter: (
      field: keyof UserDirectoryFilterState,
      value: UserDirectoryFilterState[keyof UserDirectoryFilterState]
    ) => void;
    toggleUserFilters: () => void;
    resetUserFilters: () => void;
    requestBulkUserAction: (action: BulkUserAction) => void;
    clearUserSelection: () => void;
    previousUserDirectoryPage: () => void;
    nextUserDirectoryPage: () => void;
    closeUserDetails: () => void;
    createUser: () => void;
    openBulkUserImport: () => void;
  };
  access: {
    busy: boolean;
    canManageUsers: boolean;
  };
  i18n: {
    locale: Locale;
    t: (key: TranslationKey) => string;
  };
};

export function AdminUsersWorkspace({ state, actions, access, i18n }: AdminUsersWorkspaceProps) {
  const bulkImportForm: BulkUserImportFormState = {
    csv: state.bulkImportCsv,
    fileName: state.bulkImportFileName,
    dryRun: state.bulkImportDryRun,
    commitConfirmed: state.bulkImportCommitConfirmed,
    result: state.bulkImportResult
  };

  return (
    <section className="users-layout">
      {access.canManageUsers && state.editor === "user" && (
        <UserEditorModal
          form={state.userForm}
          busy={access.busy}
          error={state.error}
          dirty={state.userFormDirty}
          translate={i18n.t}
          onChange={actions.setUserForm}
          onSubmit={actions.saveUser}
          onClose={actions.closeEditor}
        />
      )}
      {access.canManageUsers && (
        <BulkUserImportModal
          open={state.bulkImportOpen}
          form={bulkImportForm}
          busy={access.busy}
          error={state.bulkImportError}
          translate={i18n.t}
          onClose={actions.closeBulkUserImport}
          onSubmit={actions.submitBulkUserImport}
          onFileChange={actions.readBulkUserImportFile}
          onCsvChange={actions.setBulkImportCsv}
          onUseTemplate={actions.useBulkImportTemplate}
          onDryRunChange={actions.setBulkImportDryRun}
          onCommitConfirmedChange={actions.setBulkImportCommitConfirmed}
          onReset={actions.resetBulkUserImport}
        />
      )}
      <UserDirectoryPanel
        users={state.users}
        currentUserId={state.currentUserId}
        selectedUserIdSet={state.selectedUserIdSet}
        allVisibleSelected={state.allVisibleUsersSelected}
        selectedCount={state.selectedUserCount}
        availableBulkActions={state.availableBulkUserActions}
        filters={state.userDirectoryFilters}
        filtersExpanded={state.userFiltersExpanded}
        organizationOptions={state.organizationOptions}
        page={state.activeUserDirectoryPage}
        pageStart={state.userPageStart}
        pageEnd={state.userPageEnd}
        loading={state.adminViewLoading}
        hasNextPage={state.hasNextUserDirectoryPage}
        searchQuery={state.searchQuery}
        selectedUser={state.selectedUser}
        busy={access.busy}
        locale={i18n.locale}
        canManageUsers={access.canManageUsers}
        translate={i18n.t}
        onToggleVisibleSelection={actions.toggleVisibleUserSelection}
        onToggleSelection={actions.toggleUserSelection}
        onEditUser={actions.editUser}
        onShowDetails={(id) => void actions.showUserDetails(id)}
        onResetMfa={actions.resetUserMfa}
        onAdvanceLifecycle={actions.advanceUserLifecycle}
        onEnableUser={actions.enableUser}
        onRequestConfirmation={actions.requestConfirmation}
        onFilterChange={actions.updateUserDirectoryFilter}
        onToggleFilters={actions.toggleUserFilters}
        onResetFilters={actions.resetUserFilters}
        onBulkAction={actions.requestBulkUserAction}
        onClearSelection={actions.clearUserSelection}
        onPreviousPage={actions.previousUserDirectoryPage}
        onNextPage={actions.nextUserDirectoryPage}
        onCloseDetails={actions.closeUserDetails}
        onCreateUser={actions.createUser}
        onOpenBulkImport={actions.openBulkUserImport}
      />
    </section>
  );
}
