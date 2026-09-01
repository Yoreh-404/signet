import { ChevronDown, ChevronUp, Filter } from "lucide-react";

import type { TranslationKey } from "../../i18n";
import type { OrganizationOption, UserFilter } from "../../types";
import type {
  UserDirectoryFilterState,
} from "./use-user-directory-query";
import type {
  UserLinkedIdentityFilter,
  UserLoginRegionFilter,
  UserRoleFilter,
} from "./user-directory-filter-types";

type Translator = (key: TranslationKey) => string;

type UserDirectoryFilterPanelProps = {
  filters: UserDirectoryFilterState;
  expanded: boolean;
  organizationOptions: OrganizationOption[];
  t: Translator;
  onToggleExpanded: () => void;
  onChange: (
    field: keyof UserDirectoryFilterState,
    value: UserDirectoryFilterState[keyof UserDirectoryFilterState],
  ) => void;
  onReset: () => void;
};

export function UserDirectoryFilterPanel({
  filters,
  expanded,
  organizationOptions,
  t,
  onToggleExpanded,
  onChange,
  onReset,
}: UserDirectoryFilterPanelProps) {
  return (
    <>
      <label className="filter-control">
        <span>{t("userFilter")}</span>
        <select
          value={filters.userFilter}
          onChange={(event) => onChange("userFilter", event.target.value as UserFilter)}
        >
          <option value="live">{t("liveUsers")}</option>
          <option value="active">{t("activeUsers")}</option>
          <option value="disabled">{t("disabledUsers")}</option>
          <option value="archived">{t("archivedUsers")}</option>
          <option value="authorization_code">{t("authorizationCodeUsers")}</option>
          <option value="all">{t("allUsers")}</option>
        </select>
      </label>
      <section className="user-filter-panel" aria-label={t("userFilters")}>
        <div className="user-filter-heading">
          <div>
            <Filter size={16} aria-hidden="true" />
            <strong>{t("userFilters")}</strong>
          </div>
          <button
            className="text-button"
            type="button"
            aria-expanded={expanded}
            onClick={onToggleExpanded}
          >
            {expanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
            {expanded ? t("userFiltersLess") : t("userFiltersMore")}
          </button>
        </div>
        <div className="user-filter-grid user-filter-grid-common">
          <label className="user-filter-field">
            <span>{t("filterEmail")}</span>
            <input
              value={filters.userEmailFilter}
              onChange={(event) => onChange("userEmailFilter", event.target.value)}
            />
          </label>
          <label className="user-filter-field">
            <span>{t("filterRole")}</span>
            <select
              value={filters.userRoleFilter}
              onChange={(event) => onChange("userRoleFilter", event.target.value as UserRoleFilter)}
            >
              <option value="all">{t("allRoles")}</option>
              <option value="admin">{t("admin")}</option>
              <option value="user">{t("normalUser")}</option>
            </select>
          </label>
          <div className="user-filter-field">
            <span>{t("filterRegistrationDate")}</span>
            <div className="user-date-range">
              <input
                aria-label={`${t("filterRegistrationDate")} ${t("filterDateFrom")}`}
                type="date"
                value={filters.userRegistrationFrom}
                onChange={(event) => onChange("userRegistrationFrom", event.target.value)}
              />
              <span aria-hidden="true">–</span>
              <input
                aria-label={`${t("filterRegistrationDate")} ${t("filterDateTo")}`}
                type="date"
                value={filters.userRegistrationTo}
                onChange={(event) => onChange("userRegistrationTo", event.target.value)}
              />
            </div>
          </div>
          <div className="user-filter-field">
            <span>{t("filterLastLoginDate")}</span>
            <div className="user-date-range">
              <input
                aria-label={`${t("filterLastLoginDate")} ${t("filterDateFrom")}`}
                type="date"
                value={filters.userLastLoginFrom}
                onChange={(event) => onChange("userLastLoginFrom", event.target.value)}
              />
              <span aria-hidden="true">–</span>
              <input
                aria-label={`${t("filterLastLoginDate")} ${t("filterDateTo")}`}
                type="date"
                value={filters.userLastLoginTo}
                onChange={(event) => onChange("userLastLoginTo", event.target.value)}
              />
            </div>
          </div>
        </div>
        {expanded && (
          <div className="user-filter-grid user-filter-grid-advanced">
            <label className="user-filter-field">
              <span>{t("filterPhone")}</span>
              <input
                value={filters.userPhoneFilter}
                onChange={(event) => onChange("userPhoneFilter", event.target.value)}
              />
            </label>
            <label className="user-filter-field">
              <span>{t("filterLoginRegion")}</span>
              <select
                value={filters.userLoginRegionFilter}
                onChange={(event) => onChange("userLoginRegionFilter", event.target.value as UserLoginRegionFilter)}
              >
                <option value="all">{t("allLoginRegions")}</option>
                <option value="domestic">{t("domestic")}</option>
                <option value="overseas">{t("overseas")}</option>
              </select>
            </label>
            <label className="user-filter-field">
              <span>{t("filterOrganization")}</span>
              <select
                value={filters.userOrganizationFilter}
                onChange={(event) => onChange("userOrganizationFilter", event.target.value)}
              >
                <option value="">{t("allOrganizations")}</option>
                {filters.userOrganizationFilter && !organizationOptions.some((organization) => organization.id === filters.userOrganizationFilter) && (
                  <option value={filters.userOrganizationFilter}>{filters.userOrganizationFilter}</option>
                )}
                {organizationOptions.map((organization) => (
                  <option key={organization.id} value={organization.id}>
                    {organization.name} · {organization.slug}{organization.is_active ? "" : ` · ${t("disabled")}`}
                  </option>
                ))}
              </select>
            </label>
            <label className="user-filter-field">
              <span>{t("filterLinkedIdentity")}</span>
              <select
                value={filters.userLinkedIdentityFilter}
                onChange={(event) => onChange("userLinkedIdentityFilter", event.target.value as UserLinkedIdentityFilter)}
              >
                <option value="all">{t("allIdentityStates")}</option>
                <option value="linked">{t("linkedIdentityOnly")}</option>
                <option value="unlinked">{t("unlinkedIdentityOnly")}</option>
              </select>
            </label>
          </div>
        )}
        <div className="user-filter-footer">
          <button className="text-button" type="button" onClick={onReset}>{t("resetFilters")}</button>
        </div>
      </section>
    </>
  );
}
