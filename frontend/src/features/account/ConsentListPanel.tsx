import { Ban } from "lucide-react";

import type { TranslationKey } from "../../i18n";
import { formatTime } from "../../lib/formatters";
import type { Locale, MyConsent } from "../../types";

export type ConsentListPanelProps = {
  locale: Locale;
  consents: MyConsent[];
  busy: boolean;
  canMutateAccount: boolean;
  translate: (key: TranslationKey) => string;
  onRevokeConsent: (clientId: string) => void | Promise<void>;
};

export function ConsentListPanel({
  locale,
  consents,
  busy,
  canMutateAccount,
  translate: t,
  onRevokeConsent
}: ConsentListPanelProps) {
  return (
    <div className="table-panel">
      <h3>{t("authorizedApplications")}</h3>
      <table>
        <thead><tr><th>{t("clientName")}</th><th>{t("grantedScopes")}</th><th>{t("grantedAt")}</th><th>{t("updatedAt")}</th><th></th></tr></thead>
        <tbody>
          {consents.map((consent) => (
            <tr key={consent.client_id}>
              <td>{consent.client_name ?? consent.client_id}<br /><small>{consent.client_id}</small></td>
              <td><div className="token-list">{consent.granted_scopes.map((scope) => <span key={scope}>{scope}</span>)}</div></td>
              <td>{formatTime(consent.granted_at, locale)}</td>
              <td>{formatTime(consent.updated_at, locale)}</td>
              <td className="actions">
                {canMutateAccount && <button type="button" onClick={() => onRevokeConsent(consent.client_id)} disabled={busy}><Ban size={14} />{t("revoke")}</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {consents.length === 0 && <div className="empty">{t("noAuthorizedApplications")}</div>}
    </div>
  );
}
