import type { Dispatch, SetStateAction } from "react";
import type { UserFilter } from "../../types";
import type { UserDirectoryFilterState } from "./use-user-directory-query";
import type {
  UserLinkedIdentityFilter,
  UserLoginRegionFilter,
  UserRoleFilter
} from "./user-directory-filter-types";

export type UserDirectoryFilterActionOptions = {
  resetQueryState: () => void;
  setSearchQuery: Dispatch<SetStateAction<string>>;
  setUserFilter: Dispatch<SetStateAction<UserFilter>>;
  setUserOrganizationFilter: Dispatch<SetStateAction<string>>;
  setUserFiltersExpanded: Dispatch<SetStateAction<boolean>>;
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

export function useUserDirectoryFilterActions({
  resetQueryState,
  setSearchQuery,
  setUserFilter,
  setUserOrganizationFilter,
  setUserFiltersExpanded,
  setUserEmailFilter,
  setUserRoleFilter,
  setUserRegistrationFrom,
  setUserRegistrationTo,
  setUserLastLoginFrom,
  setUserLastLoginTo,
  setUserPhoneFilter,
  setUserLoginRegionFilter,
  setUserLinkedIdentityFilter
}: UserDirectoryFilterActionOptions) {
  function updateFilter(
    field: keyof UserDirectoryFilterState,
    value: UserDirectoryFilterState[keyof UserDirectoryFilterState]
  ) {
    resetQueryState();
    switch (field) {
      case "userFilter": setUserFilter(value as UserFilter); break;
      case "userEmailFilter": setUserEmailFilter(value as string); break;
      case "userRoleFilter": setUserRoleFilter(value as UserRoleFilter); break;
      case "userRegistrationFrom": setUserRegistrationFrom(value as string); break;
      case "userRegistrationTo": setUserRegistrationTo(value as string); break;
      case "userLastLoginFrom": setUserLastLoginFrom(value as string); break;
      case "userLastLoginTo": setUserLastLoginTo(value as string); break;
      case "userPhoneFilter": setUserPhoneFilter(value as string); break;
      case "userLoginRegionFilter": setUserLoginRegionFilter(value as UserLoginRegionFilter); break;
      case "userOrganizationFilter": setUserOrganizationFilter(value as string); break;
      case "userLinkedIdentityFilter": setUserLinkedIdentityFilter(value as UserLinkedIdentityFilter); break;
      case "searchQuery": setSearchQuery(value as string); break;
    }
  }

  function resetFilters() {
    resetQueryState();
    setUserFilter("live");
    setUserOrganizationFilter("");
    setUserFiltersExpanded(false);
    setUserEmailFilter("");
    setUserRoleFilter("all");
    setUserRegistrationFrom("");
    setUserRegistrationTo("");
    setUserLastLoginFrom("");
    setUserLastLoginTo("");
    setUserPhoneFilter("");
    setUserLoginRegionFilter("all");
    setUserLinkedIdentityFilter("all");
  }

  return { updateFilter, resetFilters };
}
