import { KeyRound, Save, Shield } from "lucide-react";

import { Field, StatusBadge } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { MfaStatus, TotpSetup } from "../../types";

export type MfaSecurityPanelProps = {
  mfaStatus: MfaStatus | null;
  totpSetup: TotpSetup | null;
  totpSetupCode: string;
  recoveryCodes: string[];
  busy: boolean;
  canMutateAccount: boolean;
  translate: (key: TranslationKey) => string;
  onStartTotpSetup: () => void | Promise<void>;
  onConfirmTotpSetup: () => void | Promise<void>;
  onDisableMfa: () => void | Promise<void>;
  onRotateRecoveryCodes: () => void | Promise<void>;
  onTotpSetupCodeChange: (value: string) => void;
};

export function MfaSecurityPanel({
  mfaStatus,
  totpSetup,
  totpSetupCode,
  recoveryCodes,
  busy,
  canMutateAccount,
  translate: t,
  onStartTotpSetup,
  onConfirmTotpSetup,
  onDisableMfa,
  onRotateRecoveryCodes,
  onTotpSetupCodeChange
}: MfaSecurityPanelProps) {
  return (
    <section className="panel security-card security-mfa-card" aria-labelledby="security-mfa-heading">
      <div className="security-card-heading">
        <div className="security-card-title">
          <span className="security-card-icon" aria-hidden="true"><Shield size={18} /></span>
          <div>
            <h3 id="security-mfa-heading">{t("mfaSettings")}</h3>
            <p>{t("recoveryCodesRemaining")}: {mfaStatus?.recovery_codes_remaining ?? 0}/{mfaStatus?.recovery_codes_total ?? 0}</p>
          </div>
        </div>
        <StatusBadge tone={mfaStatus?.enabled ? "success" : "neutral"}>
          <Shield size={13} aria-hidden="true" />
          {mfaStatus?.enabled ? t("active") : t("disabled")}
        </StatusBadge>
      </div>
      {canMutateAccount && (
        <div className="actions security-card-actions">
          <button className="security-action-primary" type="button" onClick={onStartTotpSetup} disabled={busy}>
            <KeyRound size={14} />{t("startTotpSetup")}
          </button>
          {mfaStatus?.enabled && (
            <button type="button" onClick={onRotateRecoveryCodes} disabled={busy}>{t("rotateRecoveryCodes")}</button>
          )}
          {mfaStatus?.enabled && (
            <button className="danger-button" type="button" onClick={onDisableMfa} disabled={busy}>{t("disableMfa")}</button>
          )}
        </div>
      )}
      {totpSetup && canMutateAccount && (
        <div className="mfa-setup security-mfa-setup">
          <label htmlFor="security-totp-secret">{t("totpSecret")}</label>
          <textarea id="security-totp-secret" readOnly value={totpSetup.secret} />
          <label htmlFor="security-otpauth-uri">{t("otpauthUri")}</label>
          <textarea id="security-otpauth-uri" readOnly value={totpSetup.otpauth_uri} />
          <Field label={t("mfaCode")} value={totpSetupCode} onChange={onTotpSetupCodeChange} />
          <div className="actions">
            <button className="security-action-primary" type="button" onClick={onConfirmTotpSetup} disabled={busy}>
              <Save size={14} />{t("confirmTotp")}
            </button>
          </div>
        </div>
      )}
      {recoveryCodes.length > 0 && (
        <div className="info security-recovery-codes">
          <strong>{t("recoveryCodes")}</strong>
          <p>{t("recoveryCodesOnce")}</p>
          <div className="token-list">
            {recoveryCodes.map((code) => <span key={code}>{code}</span>)}
          </div>
        </div>
      )}
    </section>
  );
}
