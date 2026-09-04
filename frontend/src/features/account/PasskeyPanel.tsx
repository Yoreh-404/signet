import { KeyRound, Trash2 } from "lucide-react";

import { Field } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { formatTime, shortSessionId } from "../../lib/formatters";
import type { Locale, Passkey } from "../../types";

export type PasskeyPanelProps = {
  locale: Locale;
  passkeyName: string;
  passkeys: Passkey[];
  busy: boolean;
  canMutateAccount: boolean;
  translate: (key: TranslationKey) => string;
  onPasskeyNameChange: (value: string) => void;
  onRegisterPasskey: () => void | Promise<void>;
  onDeletePasskey: (id: string) => void | Promise<void>;
};

export function PasskeyPanel({
  locale,
  passkeyName,
  passkeys,
  busy,
  canMutateAccount,
  translate: t,
  onPasskeyNameChange,
  onRegisterPasskey,
  onDeletePasskey
}: PasskeyPanelProps) {
  return (
    <div className="panel">
      <h3>{t("passkeys")}</h3>
      {canMutateAccount && (
        <div className="inline-code">
          <Field label={t("passkeyName")} value={passkeyName} onChange={onPasskeyNameChange} />
          <button type="button" onClick={onRegisterPasskey} disabled={busy}><KeyRound size={14} />{t("registerPasskey")}</button>
        </div>
      )}
      <table>
        <thead><tr><th>{t("passkeyName")}</th><th>{t("credentialId")}</th><th>{t("lastUsed")}</th><th></th></tr></thead>
        <tbody>
          {passkeys.map((passkey) => (
            <tr key={passkey.id}>
              <td>{passkey.name}<br /><small>{formatTime(passkey.created_at, locale)}</small></td>
              <td><code>{shortSessionId(passkey.credential_id)}</code></td>
              <td>{formatTime(passkey.last_used_at, locale)}</td>
              <td className="actions">
                {canMutateAccount && <button type="button" onClick={() => onDeletePasskey(passkey.id)} disabled={busy}><Trash2 size={14} />{t("delete")}</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {passkeys.length === 0 && <div className="empty">{t("noPasskeys")}</div>}
    </div>
  );
}
