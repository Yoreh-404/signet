import { Clock3, Ticket } from "lucide-react";
import { EmptyState, Modal } from "../../components/ui";
import { formatTime } from "../../lib/formatters";
import type { TranslationKey } from "../../i18n";
import type {
  Invitation,
  InvitationRedemption,
  Locale
} from "../../types";

export type InvitationRedemptionsModalProps = {
  invitation: Pick<Invitation, "code_prefix" | "uses_count" | "max_uses">;
  items: readonly InvitationRedemption[];
  nextCursor: string | null;
  loading: boolean;
  error: string;
  locale: Locale;
  t: (key: TranslationKey) => string;
  onClose: () => void;
  onLoadMore: () => void;
};

/** Pure presentation for the paginated redemption read model. */
export function InvitationRedemptionsModal({
  invitation,
  items,
  nextCursor,
  loading,
  error,
  locale,
  t,
  onClose,
  onLoadMore
}: InvitationRedemptionsModalProps) {
  return (
    <Modal
      title={t("authorizationCodeRedemptionsTitle")}
      closeLabel={t("close")}
      error={error}
      onClose={onClose}
      className="invitation-redemptions-modal"
    >
      <div className="invitation-redemptions-content">
        <div className="invitation-redemptions-summary">
          <code>{invitation.code_prefix}...</code>
          <span>{invitation.uses_count}/{invitation.max_uses ?? t("unlimited")}</span>
        </div>
        {loading && items.length === 0 ? (
          <div className="muted">{t("loading")}</div>
        ) : items.length === 0 ? (
          <EmptyState title={t("noAuthorizationCodeRedemptions")} icon={<Ticket size={22} />} />
        ) : (
          <div className="invitation-redemption-list">
            {items.map((redemption) => (
              <article className="invitation-redemption-row" key={redemption.id}>
                <strong>{redemption.user_email ?? redemption.user_username ?? redemption.user_id}</strong>
                <span>{formatTime(redemption.redeemed_at, locale)}</span>
              </article>
            ))}
          </div>
        )}
        {nextCursor && (
          <button type="button" onClick={onLoadMore} disabled={loading}>
            {loading ? t("loading") : t("loadMore")}
          </button>
        )}
      </div>
    </Modal>
  );
}
