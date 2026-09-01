import { useState } from "react";
import { emptyUserForm } from "../../lib/form-defaults";
import type { BulkUserImportResult, UserDetail, UserFilter } from "../../types";
import type {
  UserLinkedIdentityFilter,
  UserLoginRegionFilter,
  UserRoleFilter,
} from "../users/user-directory-filter-types";

export type { UserLinkedIdentityFilter, UserLoginRegionFilter, UserRoleFilter } from "../users/user-directory-filter-types";

/** Owns the users directory query controls, selection, editor, and import UI. */
export function useUserController() {
  const [selectedUser, setSelectedUser] = useState<UserDetail | null>(null);
  const [userFilter, setUserFilter] = useState<UserFilter>("live");
  const [userOrganizationFilter, setUserOrganizationFilter] = useState("");
  const [userFiltersExpanded, setUserFiltersExpanded] = useState(false);
  const [userEmailFilter, setUserEmailFilter] = useState("");
  const [userRoleFilter, setUserRoleFilter] = useState<UserRoleFilter>("all");
  const [userRegistrationFrom, setUserRegistrationFrom] = useState("");
  const [userRegistrationTo, setUserRegistrationTo] = useState("");
  const [userLastLoginFrom, setUserLastLoginFrom] = useState("");
  const [userLastLoginTo, setUserLastLoginTo] = useState("");
  const [userPhoneFilter, setUserPhoneFilter] = useState("");
  const [userLoginRegionFilter, setUserLoginRegionFilter] = useState<UserLoginRegionFilter>("all");
  const [userLinkedIdentityFilter, setUserLinkedIdentityFilter] = useState<UserLinkedIdentityFilter>("all");
  const [userDirectoryPage, setUserDirectoryPage] = useState(1);
  // Each entry is the cursor used to request the corresponding page. The
  // first page starts at null; retaining prior positions makes Previous
  // bounded without recreating an OFFSET query.
  const [userDirectoryCursorHistory, setUserDirectoryCursorHistory] = useState<Array<string | null>>([null]);
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [userForm, setUserForm] = useState(emptyUserForm);
  const [userFormBaseline, setUserFormBaseline] = useState<typeof emptyUserForm | null>(null);
  const [bulkImportOpen, setBulkImportOpen] = useState(false);
  const [bulkImportCsv, setBulkImportCsv] = useState("");
  const [bulkImportFileName, setBulkImportFileName] = useState("");
  const [bulkImportDryRun, setBulkImportDryRun] = useState(true);
  const [bulkImportCommitConfirmed, setBulkImportCommitConfirmed] = useState(false);
  const [bulkImportResult, setBulkImportResult] = useState<BulkUserImportResult | null>(null);
  const [bulkImportError, setBulkImportError] = useState("");

  return {
    selectedUser,
    setSelectedUser,
    userFilter,
    setUserFilter,
    userOrganizationFilter,
    setUserOrganizationFilter,
    userFiltersExpanded,
    setUserFiltersExpanded,
    userEmailFilter,
    setUserEmailFilter,
    userRoleFilter,
    setUserRoleFilter,
    userRegistrationFrom,
    setUserRegistrationFrom,
    userRegistrationTo,
    setUserRegistrationTo,
    userLastLoginFrom,
    setUserLastLoginFrom,
    userLastLoginTo,
    setUserLastLoginTo,
    userPhoneFilter,
    setUserPhoneFilter,
    userLoginRegionFilter,
    setUserLoginRegionFilter,
    userLinkedIdentityFilter,
    setUserLinkedIdentityFilter,
    userDirectoryPage,
    setUserDirectoryPage,
    userDirectoryPageSize: 25,
    userDirectoryCursorHistory,
    setUserDirectoryCursorHistory,
    selectedUserIds,
    setSelectedUserIds,
    userForm,
    setUserForm,
    userFormBaseline,
    setUserFormBaseline,
    bulkImportOpen,
    setBulkImportOpen,
    bulkImportCsv,
    setBulkImportCsv,
    bulkImportFileName,
    setBulkImportFileName,
    bulkImportDryRun,
    setBulkImportDryRun,
    bulkImportCommitConfirmed,
    setBulkImportCommitConfirmed,
    bulkImportResult,
    setBulkImportResult,
    bulkImportError,
    setBulkImportError
  };
}

export type UserController = ReturnType<typeof useUserController>;
