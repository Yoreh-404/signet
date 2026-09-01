import { FileUp, Plus, Users } from "lucide-react";
import { EmptyState, Modal } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { Locale, OrganizationOption, User, UserDetail } from "../../types";
import type { UserDirectoryFilterState } from "./use-user-directory-query";
import type { BulkUserAction } from "./user-lifecycle";
import { UserBulkActionsToolbar } from "./UserBulkActionsToolbar";
import { UserDetailPanel } from "./UserDetailPanel";
import { UserDirectoryFilterPanel } from "./UserDirectoryFilterPanel";
import { UserDirectoryPagination } from "./UserDirectoryPagination";
import { UserTable } from "./UserTable";

type Translate = (key: TranslationKey) => string;
type FilterChange = (
  field: keyof UserDirectoryFilterState,
  value: UserDirectoryFilterState[keyof UserDirectoryFilterState]
) => void;

export type UserDirectoryPanelProps = {
  users: User[];
  currentUserId?: string;
  selectedUserIdSet: ReadonlySet<string>;
  allVisibleSelected: boolean;
  selectedCount: number;
  availableBulkActions: readonly BulkUserAction[];
  filters: UserDirectoryFilterState;
  filtersExpanded: boolean;
  organizationOptions: OrganizationOption[];
  page: number;
  pageStart: number;
  pageEnd: number;
  loading: boolean;
  hasNextPage: boolean;
  searchQuery: string;
  selectedUser: UserDetail | null;
  busy: boolean;
  locale: Locale;
  canManageUsers: boolean;
  translate: Translate;
  onToggleVisibleSelection: (checked: boolean) => void;
  onToggleSelection: (id: string) => void;
  onEditUser: (user: User) => void;
  onShowDetails: (id: string) => void;
  onResetMfa: (id: string) => void | Promise<void>;
  onAdvanceLifecycle: (id: string) => void | Promise<void>;
  onEnableUser: (id: string) => void | Promise<void>;
  onRequestConfirmation: (action: () => void | Promise<void>) => void;
  onFilterChange: FilterChange;
  onToggleFilters: () => void;
  onResetFilters: () => void;
  onBulkAction: (action: BulkUserAction) => void;
  onClearSelection: () => void;
  onPreviousPage: () => void;
  onNextPage: () => void;
  onCloseDetails: () => void;
  onCreateUser: () => void;
  onOpenBulkImport: () => void;
};

export function UserDirectoryPanel({
  users,
  currentUserId,
  selectedUserIdSet,
  allVisibleSelected,
  selectedCount,
  availableBulkActions,
  filters,
  filtersExpanded,
  organizationOptions,
  page,
  pageStart,
  pageEnd,
  loading,
  hasNextPage,
  searchQuery,
  selectedUser,
  busy,
  locale,
  canManageUsers,
  translate,
  onToggleVisibleSelection,
  onToggleSelection,
  onEditUser,
  onShowDetails,
  onResetMfa,
  onAdvanceLifecycle,
  onEnableUser,
  onRequestConfirmation,
  onFilterChange,
  onToggleFilters,
  onResetFilters,
  onBulkAction,
  onClearSelection,
  onPreviousPage,
  onNextPage,
  onCloseDetails,
  onCreateUser,
  onOpenBulkImport
}: UserDirectoryPanelProps) {
  return (
    <div className="table-panel users-table-panel">
      <div className="table-toolbar users-toolbar">
        <div className="users-toolbar-actions">
          {canManageUsers && <button type="button" onClick={onCreateUser}><Plus size={14} />{translate("createUser")}</button>}
          {canManageUsers && <button type="button" onClick={onOpenBulkImport}><FileUp size={14} />{translate("bulkUserImport")}</button>}
        </div>
      </div>
      <UserDirectoryFilterPanel
        filters={filters}
        expanded={filtersExpanded}
        organizationOptions={organizationOptions}
        t={translate}
        onToggleExpanded={onToggleFilters}
        onChange={onFilterChange}
        onReset={onResetFilters}
      />
      {canManageUsers && <UserBulkActionsToolbar
        selectedCount={selectedCount}
        availableActions={availableBulkActions}
        busy={busy}
        translate={translate}
        onAction={onBulkAction}
        onClear={onClearSelection}
      />}
      <UserTable
        users={users}
        canManageUsers={canManageUsers}
        currentUserId={currentUserId}
        selectedUserIdSet={selectedUserIdSet}
        allVisibleSelected={allVisibleSelected}
        busy={busy}
        locale={locale}
        translate={translate}
        onToggleVisibleSelection={onToggleVisibleSelection}
        onToggleSelection={onToggleSelection}
        onEditUser={onEditUser}
        onShowDetails={onShowDetails}
        onResetMfa={onResetMfa}
        onAdvanceLifecycle={onAdvanceLifecycle}
        onEnableUser={onEnableUser}
        onRequestConfirmation={onRequestConfirmation}
      />
      <UserDirectoryPagination
        page={page}
        start={pageStart}
        end={pageEnd}
        loading={loading}
        hasNextPage={hasNextPage}
        translate={translate}
        onPrevious={onPreviousPage}
        onNext={onNextPage}
      />
      {!loading && users.length === 0 && (
        <EmptyState title={searchQuery ? translate("noSearchResults") : translate("noData")} icon={<Users size={22} />} />
      )}
      {selectedUser && (
        <Modal title={translate("userDetails")} closeLabel={translate("close")} onClose={onCloseDetails} wide className="user-detail-modal">
          <UserDetailPanel detail={selectedUser} locale={locale} t={translate} />
        </Modal>
      )}
    </div>
  );
}
