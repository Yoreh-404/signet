import { useCallback, useEffect, useMemo, useRef } from "react";
import type { Dispatch, SetStateAction } from "react";

import type { UserFilter } from "../../types";
import type {
  UserLinkedIdentityFilter,
  UserLoginRegionFilter,
  UserRoleFilter,
} from "./user-directory-filter-types";
import { serializeUserDirectoryQuery } from "./user-directory";
import type { UserDirectoryQueryInput } from "./user-directory";

export type UserDirectoryFilterState = {
  searchQuery: string;
  userFilter: UserFilter;
  userOrganizationFilter: string;
  userEmailFilter: string;
  userRoleFilter: UserRoleFilter;
  userRegistrationFrom: string;
  userRegistrationTo: string;
  userLastLoginFrom: string;
  userLastLoginTo: string;
  userPhoneFilter: string;
  userLoginRegionFilter: UserLoginRegionFilter;
  userLinkedIdentityFilter: UserLinkedIdentityFilter;
};

type UserDirectoryQueryControls = {
  userDirectoryPage: number;
  userDirectoryPageSize: number;
  userDirectoryCursorHistory: Array<string | null>;
  setUserDirectoryPage: Dispatch<SetStateAction<number>>;
  setUserDirectoryCursorHistory: Dispatch<SetStateAction<Array<string | null>>>;
  setSelectedUserIds: Dispatch<SetStateAction<string[]>>;
};

function directoryQueryFromFilters(
  filters: UserDirectoryFilterState,
  pageSize: number,
): UserDirectoryQueryInput {
  return {
    page_size: pageSize,
    status: filters.userFilter,
    search: filters.searchQuery,
    organization_id: filters.userOrganizationFilter,
    linked_identity: filters.userLinkedIdentityFilter === "all"
      ? undefined
      : filters.userLinkedIdentityFilter,
    email: filters.userEmailFilter,
    phone: filters.userPhoneFilter,
    role: filters.userRoleFilter === "all" ? undefined : filters.userRoleFilter,
    registration_from: filters.userRegistrationFrom,
    registration_to: filters.userRegistrationTo,
    last_login_from: filters.userLastLoginFrom,
    last_login_to: filters.userLastLoginTo,
    login_region: filters.userLoginRegionFilter === "all"
      ? undefined
      : filters.userLoginRegionFilter,
  };
}

export function useUserDirectoryQuery(
  filters: UserDirectoryFilterState,
  {
    userDirectoryPage,
    userDirectoryPageSize,
    userDirectoryCursorHistory,
    setUserDirectoryPage,
    setUserDirectoryCursorHistory,
    setSelectedUserIds,
  }: UserDirectoryQueryControls,
) {
  const baseQuery = useMemo(
    () => directoryQueryFromFilters(filters, userDirectoryPageSize),
    [
      filters.searchQuery,
      filters.userEmailFilter,
      filters.userFilter,
      filters.userLastLoginFrom,
      filters.userLastLoginTo,
      filters.userLinkedIdentityFilter,
      filters.userLoginRegionFilter,
      filters.userOrganizationFilter,
      filters.userPhoneFilter,
      filters.userRegistrationFrom,
      filters.userRegistrationTo,
      filters.userRoleFilter,
      userDirectoryPageSize,
    ],
  );
  const filterKey = useMemo(
    () => serializeUserDirectoryQuery({ ...baseQuery, page: 1, cursor: undefined }),
    [baseQuery],
  );
  const previousFilterKey = useRef(filterKey);
  const filterTransition = previousFilterKey.current !== filterKey;

  useEffect(() => {
    if (previousFilterKey.current === filterKey) return;
    previousFilterKey.current = filterKey;
    setUserDirectoryPage(1);
    setUserDirectoryCursorHistory([null]);
    setSelectedUserIds([]);
  }, [filterKey, setSelectedUserIds, setUserDirectoryCursorHistory, setUserDirectoryPage]);

  useEffect(() => {
    setSelectedUserIds([]);
  }, [setSelectedUserIds, userDirectoryPage]);

  const query = useMemo<UserDirectoryQueryInput>(() => ({
    ...baseQuery,
    page: filterTransition ? 1 : userDirectoryPage,
    cursor: filterTransition
      ? undefined
      : userDirectoryCursorHistory[userDirectoryPage - 1] ?? undefined,
  }), [
    baseQuery,
    filterTransition,
    userDirectoryCursorHistory,
    userDirectoryPage,
  ]);

  const resetQueryState = useCallback(() => {
    setUserDirectoryPage(1);
    setUserDirectoryCursorHistory([null]);
    setSelectedUserIds([]);
  }, [setSelectedUserIds, setUserDirectoryCursorHistory, setUserDirectoryPage]);

  return { filterKey, filterTransition, query, resetQueryState };
}
