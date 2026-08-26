import type { LucideIcon } from "lucide-react";
import { ArrowLeftRight, LogOut, Shield, UserRound } from "lucide-react";
import type { ReactNode, Ref } from "react";

import type { Tab, User } from "../../types";

export type AdminSidebarNavigationItem = {
  id: Tab;
  label: string;
  icon: LucideIcon;
};

export type AdminSidebarNavigationGroup = {
  id: string;
  label: string;
  items: AdminSidebarNavigationItem[];
};

export type AdminSidebarProps = {
  open: boolean;
  sidebarRef: Ref<HTMLElement>;
  tab: Tab;
  user: Pick<User, "username" | "email" | "is_admin">;
  navigationGroups: AdminSidebarNavigationGroup[];
  languageControl: ReactNode;
  labels: {
    closeNavigation: string;
    adminConsole: string;
    account: string;
    email: string;
    username: string;
    role: string;
    admin: string;
    normalUser: string;
    switchAccount: string;
    logout: string;
  };
  busy: boolean;
  onClose: () => void;
  onNavigate: (tab: Tab) => void;
  onSwitchAccount: () => void;
  onLogout: () => void;
};

export function AdminSidebar({
  open,
  sidebarRef,
  tab,
  user,
  navigationGroups,
  languageControl,
  labels,
  busy,
  onClose,
  onNavigate,
  onSwitchAccount,
  onLogout
}: AdminSidebarProps) {
  return (
    <>
      <button
        type="button"
        className={`sidebar-scrim ${open ? "visible" : ""}`}
        aria-label={labels.closeNavigation}
        aria-hidden={!open}
        tabIndex={open ? 0 : -1}
        onClick={onClose}
      />
      <aside
        id="admin-navigation"
        ref={sidebarRef}
        className={open ? "sidebar-open" : ""}
        aria-label={labels.adminConsole}
      >
        <div className="brand-row compact">
          <span className="brand-mark"><Shield size={22} /></span>
          <div><h1>Signet</h1></div>
        </div>
        {languageControl}
        <nav aria-label={labels.adminConsole}>
          {navigationGroups.map((group) => (
            <div className="nav-group" key={group.id}>
              <p className="nav-group-label">{group.label}</p>
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    type="button"
                    key={item.id}
                    className={tab === item.id ? "active" : ""}
                    onClick={() => onNavigate(item.id)}
                    aria-current={tab === item.id ? "page" : undefined}
                    aria-label={item.label}
                    title={item.label}
                  >
                    <Icon size={18} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <button
            className={`account-card ${tab === "account" ? "active" : ""}`}
            type="button"
            onClick={() => onNavigate("account")}
            aria-label={labels.account}
            aria-current={tab === "account" ? "page" : undefined}
            aria-describedby="account-tooltip"
          >
            <UserRound size={18} />
            <span className="account-card-copy">
              <strong>{user.username}</strong>
              <small>{user.email}</small>
            </span>
            <span id="account-tooltip" className="account-tooltip" role="tooltip">
              <strong>{labels.account}</strong>
              <span>{labels.email}: {user.email}</span>
              <span>{labels.username}: {user.username}</span>
              <span>{labels.role}: {user.is_admin ? labels.admin : labels.normalUser}</span>
            </span>
          </button>
          <button
            className="ghost account-switch-button"
            type="button"
            onClick={onSwitchAccount}
            title={labels.switchAccount}
            aria-label={labels.switchAccount}
            disabled={busy}
          >
            <ArrowLeftRight size={18} />
          </button>
          <button
            className="ghost logout-button"
            type="button"
            onClick={onLogout}
            title={labels.logout}
            aria-label={labels.logout}
            disabled={busy}
          >
            <LogOut size={18} />
          </button>
        </div>
      </aside>
    </>
  );
}
