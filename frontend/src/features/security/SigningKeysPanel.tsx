import { KeyRound, RotateCcw } from "lucide-react";

import { Field, StatusBadge } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { formatTime } from "../../lib/formatters";
import type { Locale, SigningKey } from "../../types";

export type SigningKeysPanelProps = {
  signingKeys: SigningKey[];
  signingKeyKid: string;
  busy: boolean;
  locale: Locale;
  translate: (key: TranslationKey) => string;
  onSigningKeyKidChange: (value: string) => void;
  onRotate: () => void | Promise<void>;
};

export function SigningKeysPanel({
  signingKeys,
  signingKeyKid,
  busy,
  locale,
  translate: t,
  onSigningKeyKidChange,
  onRotate
}: SigningKeysPanelProps) {
  const hasActiveKey = signingKeys.some((key) => key.is_active);

  return (
    <section className="table-panel security-card security-signing-card" aria-labelledby="security-signing-keys-heading">
      <div className="security-card-heading">
        <div className="security-card-title">
          <span className="security-card-icon" aria-hidden="true"><KeyRound size={18} /></span>
          <div>
            <h3 id="security-signing-keys-heading">{t("signingKeys")}</h3>
            <p>{t("keyId")}</p>
          </div>
        </div>
        <StatusBadge tone={hasActiveKey ? "success" : "warning"}>
          {hasActiveKey ? t("activeSigningKey") : t("retiredSigningKey")}
        </StatusBadge>
      </div>
      <div className="security-key-controls">
        <Field label={t("keyId")} value={signingKeyKid} onChange={onSigningKeyKidChange} />
        <button className="security-action-primary" type="button" onClick={onRotate} disabled={busy}>
          <RotateCcw size={14} />{t("rotateSigningKey")}
        </button>
      </div>
      <table className="security-signing-table">
        <thead>
          <tr>
            <th>{t("keyId")}</th>
            <th>{t("status")}</th>
            <th>{t("registeredAt")}</th>
            <th>{t("activatedAt")}</th>
            <th>{t("retiredAt")}</th>
          </tr>
        </thead>
        <tbody>
          {signingKeys.map((key) => (
            <tr key={key.id}>
              <td>{key.kid}</td>
              <td>{key.is_active ? t("activeSigningKey") : t("retiredSigningKey")}</td>
              <td>{formatTime(key.created_at, locale)}</td>
              <td>{formatTime(key.activated_at, locale)}</td>
              <td>{formatTime(key.retired_at, locale)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {signingKeys.length === 0 && <div className="empty">{t("noData")}</div>}
    </section>
  );
}
