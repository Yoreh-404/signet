import type { Dispatch, SetStateAction } from "react";

import type { UserFilter } from "../../types";
import { useUserDirectoryFilterActions } from "./use-user-directory-filter-actions";
import { useUserDirectoryQuery, type UserDirectoryFilterState } from "./use-user-directory-query";
import type {
  UserLinkedIdentityFilter,
  UserLoginRegionFilter,
  UserRoleFilter
} from "./user-directory-filter-types";

export type UserDirectoryFacadeOptions = {
  filters: UserDirectoryFilterState;
  page: number;
  pageSize: number;
  cursorHistory: Array<string | null>;
  setPage: Dispatch<SetStateAction<number>>;
  setCursorHistory: Dispatch<SetStateAction<Array<string | null>>>;
  setSelectedIds: Dispatch<SetStateAction<string[]>>;
  setSearchQuery: Dispatch<SetStateAction<string>>;
  setUserFilter: Dispatch<SetStateAction<UserFilter>>;
  setUserOrganizationFilter: Dispatch<SetStateAction<string>>;
  setFiltersExpanded: Dispatch<SetStateAction<boolean>>;
  setUserEmailFilter: Dispatch<SetStateAction<string>>;
  setUserRoleFilter: Dispatch<SetStateAction<UserRoleFilter>>;
  setUserRegistrationFrom: Dispatch<SetStateAction<string>>;
  setUserRegistrationTo: Dispatch<SetStateAction<string>>;
  setUserLastLoginFrom: Dispatch<SetStateAction<string>>;
  setUserLastLoginTo: Dispatch<SetStateAction<string>>;
  setUserPhoneFilter: Dispatch<SetStateAction<string>>;
  setUserLoginRegionFilter: Dispatch<SetStateAction<UserLoginRegionFilter>>;
  setUserLinkedIdentityFilter: Dispatch<SetStateAction<UserLinkedIdentityFilter>>;
};

export function useUserDirectoryFacade({
  filters,
  page,
  pageSize,
  cursorHistory,
  setPage,
  setCursorHistory,
  setSelectedIds,
  setSearchQuery,
  setUserFilter,
  setUserOrganizationFilter,
  setFiltersExpanded,
  setUserEmailFilter,
  setUserRoleFilter,
  setUserRegistrationFrom,
  setUserRegistrationTo,
  setUserLastLoginFrom,
  setUserLastLoginTo,
  setUserPhoneFilter,
  setUserLoginRegionFilter,
  setUserLinkedIdentityFilter
}: UserDirectoryFacadeOptions) {
  const queryModel = useUserDirectoryQuery(filters, {
    userDirectoryPage: page,
    userDirectoryPageSize: pageSize,
    userDirectoryCursorHistory: cursorHistory,
    setUserDirectoryPage: setPage,
    setUserDirectoryCursorHistory: setCursorHistory,
    setSelectedUserIds: setSelectedIds
  });
  const filterActions = useUserDirectoryFilterActions({
    resetQueryState: queryModel.resetQueryState,
    setSearchQuery,
    setUserFilter,
    setUserOrganizationFilter,
    setUserFiltersExpanded: setFiltersExpanded,
    setUserEmailFilter,
    setUserRoleFilter,
    setUserRegistrationFrom,
    setUserRegistrationTo,
    setUserLastLoginFrom,
    setUserLastLoginTo,
    setUserPhoneFilter,
    setUserLoginRegionFilter,
    setUserLinkedIdentityFilter
  });

  return {
    ...queryModel,
    filters,
    updateFilter: filterActions.updateFilter,
    resetFilters: filterActions.resetFilters
  };
}
