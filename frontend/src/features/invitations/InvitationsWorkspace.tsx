import { Copy } from "lucide-react";
import type { FormEvent } from "react";

import { Modal } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { Client, Invitation, Locale, OrganizationOption } from "../../types";
import {
  AuthorizationCodesWorkspace,
  type AuthorizationCodesForm
} from "./AuthorizationCodesWorkspace";
import { InvitationRedemptionsModal } from "./InvitationRedemptionsModal";
import type { InvitationRedemptionsController } from "./useInvitationRedemptions";

export type InvitationsWorkspaceProps = {
  open: boolean;
  form: AuthorizationCodesForm;
  clients: Client[];
  organizations: OrganizationOption[];
  filteredInvitations: Invitation[];
  canManageOrganizations: boolean;
  isAdmin: boolean;
  busy: boolean;
  error: string;
  dirty: boolean;
  adminViewLoading: boolean;
  searchQuery: string;
  locale: Locale;
  lastInvitationCode: string;
  revealedInvitation: Invitation | null;
  revealedInvitationCode: string;
  revealingInvitationId: string;
  invitationRevealError: string;
  redemptions: InvitationRedemptionsController;
  redemptionsError: string;
  translate: (key: TranslationKey) => string;
  onChange: (form: AuthorizationCodesForm) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onClose: () => void;
  onCreate: () => void;
  onEdit: (invitation: Invitation) => void;
  onDelete: (id: string) => void;
  onReveal: (invitation: Invitation) => void;
  onOpenRedemptions: (invitation: Invitation) => void;
  onCloseReveal: () => void;
  onCopyLastInvitationCode: () => void;
  onCopyRevealedInvitationCode: () => void;
};

export function InvitationsWorkspace({
  open,
  form,
  clients,
  organizations,
  filteredInvitations,
  canManageOrganizations,
  isAdmin,
  busy,
  error,
  dirty,
  adminViewLoading,
  searchQuery,
  locale,
  lastInvitationCode,
  revealedInvitation,
  revealedInvitationCode,
  revealingInvitationId,
  invitationRevealError,
  redemptions,
  redemptionsError,
  translate,
  onChange,
  onSubmit,
  onClose,
  onCreate,
  onEdit,
  onDelete,
  onReveal,
  onOpenRedemptions,
  onCloseReveal,
  onCopyLastInvitationCode,
  onCopyRevealedInvitationCode
}: InvitationsWorkspaceProps) {
  return (
    <section className="management-list">
      <AuthorizationCodesWorkspace
        open={open}
        form={form}
        clients={clients}
        organizations={organizations}
        filteredInvitations={filteredInvitations}
        canManageOrganizations={canManageOrganizations}
        isAdmin={isAdmin}
        busy={busy}
        error={error}
        dirty={dirty}
        adminViewLoading={adminViewLoading}
        searchQuery={searchQuery}
        locale={locale}
        lastInvitationCode={lastInvitationCode}
        revealingInvitationId={revealingInvitationId}
        translate={translate}
        onChange={onChange}
        onSubmit={onSubmit}
        onClose={onClose}
        onCreate={onCreate}
        onEdit={onEdit}
        onDelete={onDelete}
        onReveal={onReveal}
        onCopyLastInvitationCode={onCopyLastInvitationCode}
        onOpenRedemptions={onOpenRedemptions}
      />
      {revealedInvitation && (
        <Modal
          title={translate("authorizationCodeRevealTitle")}
          closeLabel={translate("close")}
          error={invitationRevealError}
          onClose={onCloseReveal}
          className="invitation-reveal-modal"
        >
          <div className="invitation-reveal-content">
            <p>{translate("authorizationCodeRevealHint")}</p>
            {revealingInvitationId === revealedInvitation.id ? (
              <div className="muted">{translate("loading")}</div>
            ) : revealedInvitationCode ? (
              <div className="invitation-secret-value">
                <code>{revealedInvitationCode}</code>
                <button
                  className="link-button"
                  type="button"
                  onClick={onCopyRevealedInvitationCode}
                >
                  <Copy size={14} />
                  {translate("copyAuthorizationCode")}
                </button>
              </div>
            ) : null}
          </div>
        </Modal>
      )}
      {redemptions.invitation && (
        <InvitationRedemptionsModal
          invitation={redemptions.invitation}
          items={redemptions.items}
          nextCursor={redemptions.nextCursor}
          loading={redemptions.loading}
          error={redemptionsError}
          locale={locale}
          t={translate}
          onClose={redemptions.close}
          onLoadMore={() => void redemptions.loadMore()}
        />
      )}
    </section>
  );
}
