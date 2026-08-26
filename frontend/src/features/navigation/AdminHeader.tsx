import { Building2, Menu, Moon, Plus, RefreshCw, Sun } from "lucide-react";
import type { Ref } from "react";

import { SearchField } from "../../components/ui";
import type { Tab, Theme, UserOrganization } from "../../types";

export type AdminHeaderTab = { id: Tab; label: string };
export type AdminHeaderNavigationGroup = { label: string; hint: string };

export type AdminHeaderProps = {
  mobileMenuButtonRef: Ref<HTMLButtonElement>;
  sidebarOpen: boolean;
  activeNavigationGroup: AdminHeaderNavigationGroup | undefined;
  tab: Tab;
  tabs: AdminHeaderTab[];
  organizationContext: UserOrganization | null;
  myOrganizations: UserOrganization[];
  searchEnabled: boolean;
  searchQuery: string;
  theme: Theme;
  refreshing: boolean;
  busy: boolean;
  labels: {
    openNavigation: string;
    enterprise: string;
    noEnterprise: string;
    switchEnterprise: string;
    systemEnterprise: string;
    createEnterprise: string;
    searchCurrentPage: string;
    clearSearch: string;
    lightMode: string;
    darkMode: string;
    refresh: string;
  };
  onOpenSidebar: () => void;
  onNavigateSearch: (value: string) => void;
  onToggleTheme: () => void;
  onRefresh: () => void;
  onSwitchEnterprise: (organizationId: string) => void;
  onCreateEnterprise: () => void;
};

export function AdminHeader({
  mobileMenuButtonRef,
  sidebarOpen,
  activeNavigationGroup,
  tab,
  tabs,
  organizationContext,
  myOrganizations,
  searchEnabled,
  searchQuery,
  theme,
  refreshing,
  busy,
  labels,
  onOpenSidebar,
  onNavigateSearch,
  onToggleTheme,
  onRefresh,
  onSwitchEnterprise,
  onCreateEnterprise
}: AdminHeaderProps) {
  return (
    <header className="page-header">
      <button
        ref={mobileMenuButtonRef}
        className="icon-button mobile-menu-button"
        type="button"
        onClick={onOpenSidebar}
        title={labels.openNavigation}
        aria-label={labels.openNavigation}
        aria-controls="admin-navigation"
        aria-expanded={sidebarOpen}
      >
        <Menu size={19} />
      </button>
      <div className="page-heading">
        {activeNavigationGroup && <span className="page-heading-context">{activeNavigationGroup.label}</span>}
        <h2>{tabs.find((item) => item.id === tab)?.label}</h2>
        {activeNavigationGroup && <small className="page-heading-hint">{activeNavigationGroup.hint}</small>}
        {organizationContext && (
          <span className="page-heading-context current-enterprise-context" aria-live="polite">
            <Building2 size={13} aria-hidden="true" />
            {labels.enterprise} · {organizationContext.name}
          </span>
        )}
      </div>
      <div className="enterprise-switcher">
        <Building2 size={16} aria-hidden="true" />
        <select
          aria-label={labels.switchEnterprise}
          value={organizationContext?.id ?? ""}
          onChange={(event) => onSwitchEnterprise(event.target.value)}
          disabled={busy || myOrganizations.length === 0}
        >
          {myOrganizations.length === 0 && <option value="">{labels.noEnterprise}</option>}
          {myOrganizations.map((organization) => (
            <option key={organization.id} value={organization.id}>
              {organization.name}{organization.kind === "system" ? ` · ${labels.systemEnterprise}` : ""}
            </option>
          ))}
        </select>
        <button
          className="icon-button"
          type="button"
          onClick={onCreateEnterprise}
          title={labels.createEnterprise}
          aria-label={labels.createEnterprise}
          disabled={busy}
        >
          <Plus size={16} />
        </button>
      </div>
      <div className="header-actions">
        {searchEnabled && (
          <SearchField
            value={searchQuery}
            onChange={onNavigateSearch}
            placeholder={labels.searchCurrentPage}
            clearLabel={labels.clearSearch}
          />
        )}
        <button className="icon-button" type="button" onClick={onToggleTheme} title={theme === "dark" ? labels.lightMode : labels.darkMode} aria-label={theme === "dark" ? labels.lightMode : labels.darkMode}>
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button className="icon-button" type="button" onClick={onRefresh} title={labels.refresh} aria-label={labels.refresh} disabled={refreshing}>
          <RefreshCw className={refreshing ? "spin" : ""} size={18} />
        </button>
      </div>
    </header>
  );
}
