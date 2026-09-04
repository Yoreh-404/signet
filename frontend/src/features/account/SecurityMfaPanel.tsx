import { KeyRound, Save } from "lucide-react";

import { Field } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import type { MfaStatus, TotpSetup } from "../../types";

export type SecurityMfaPanelProps = {
  mfaStatus: MfaStatus | null;
  totpSetup: TotpSetup | null;
  totpSetupCode: string;
  recoveryCodes: string[];
  busy: boolean;
  canMutateAccount: boolean;
  translate: (key: TranslationKey) => string;
  onStartTotpSetup: () => void | Promise<void>;
  onConfirmTotpSetup: () => void | Promise<void>;
  onRotateRecoveryCodes: () => void | Promise<void>;
  onDisableMfa: () => void | Promise<void>;
  onTotpSetupCodeChange: (value: string) => void;
};

export function SecurityMfaPanel({
  mfaStatus,
  totpSetup,
  totpSetupCode,
  recoveryCodes,
  busy,
  canMutateAccount,
  translate: t,
  onStartTotpSetup,
  onConfirmTotpSetup,
  onRotateRecoveryCodes,
  onDisableMfa,
  onTotpSetupCodeChange
}: SecurityMfaPanelProps) {
  return (
    <div className="panel">
      <h3>{t("mfaSettings")}</h3>
      <p className="muted">
        {mfaStatus?.enabled ? t("active") : t("disabled")} · {t("recoveryCodesRemaining")}: {mfaStatus?.recovery_codes_remaining ?? 0}/{mfaStatus?.recovery_codes_total ?? 0}
      </p>
      {canMutateAccount && (
        <div className="actions">
          <button type="button" onClick={onStartTotpSetup} disabled={busy}><KeyRound size={14} />{t("startTotpSetup")}</button>
          {mfaStatus?.enabled && <button type="button" onClick={onRotateRecoveryCodes} disabled={busy}>{t("rotateRecoveryCodes")}</button>}
          {mfaStatus?.enabled && <button type="button" onClick={onDisableMfa} disabled={busy}>{t("disableMfa")}</button>}
        </div>
      )}
      {totpSetup && canMutateAccount && (
        <div className="mfa-setup">
          <label htmlFor="account-totp-secret">{t("totpSecret")}</label>
          <textarea id="account-totp-secret" readOnly value={totpSetup.secret} />
          <label htmlFor="account-otpauth-uri">{t("otpauthUri")}</label>
          <textarea id="account-otpauth-uri" readOnly value={totpSetup.otpauth_uri} />
          <Field label={t("mfaCode")} value={totpSetupCode} onChange={onTotpSetupCodeChange} />
          <div className="actions">
            <button type="button" onClick={onConfirmTotpSetup} disabled={busy}><Save size={14} />{t("confirmTotp")}</button>
          </div>
        </div>
      )}
      {recoveryCodes.length > 0 && (
        <div className="info">
          <strong>{t("recoveryCodes")}</strong>
          <p>{t("recoveryCodesOnce")}</p>
          <div className="token-list">{recoveryCodes.map((code) => <span key={code}>{code}</span>)}</div>
        </div>
      )}
    </div>
  );
}
