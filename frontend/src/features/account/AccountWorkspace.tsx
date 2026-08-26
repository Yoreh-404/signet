import { Ban, KeyRound, LogOut, Save, Trash2 } from "lucide-react";

import { Field } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { formatTime, shortSessionId } from "../../lib/formatters";
import type { Locale, MfaStatus, MyConsent, MySession, Passkey, TotpSetup, User } from "../../types";

export type AccountWorkspaceProps = {
  user: User;
  locale: Locale;
  mfaStatus: MfaStatus | null;
  totpSetup: TotpSetup | null;
  totpSetupCode: string;
  recoveryCodes: string[];
  passkeyName: string;
  passkeys: Passkey[];
  mySessions: MySession[];
  myConsents: MyConsent[];
  busy: boolean;
  canMutateAccount: boolean;
  translate: (key: TranslationKey) => string;
  onStartTotpSetup: () => void | Promise<void>;
  onConfirmTotpSetup: () => void | Promise<void>;
  onRotateRecoveryCodes: () => void | Promise<void>;
  onDisableMfa: () => void | Promise<void>;
  onTotpSetupCodeChange: (value: string) => void;
  onPasskeyNameChange: (value: string) => void;
  onRegisterPasskey: () => void | Promise<void>;
  onDeletePasskey: (id: string) => void | Promise<void>;
  onRevokeSession: (id: string) => void | Promise<void>;
  onRevokeConsent: (clientId: string) => void | Promise<void>;
};

export function AccountWorkspace({
  user,
  locale,
  mfaStatus,
  totpSetup,
  totpSetupCode,
  recoveryCodes,
  passkeyName,
  passkeys,
  mySessions,
  myConsents,
  busy,
  canMutateAccount,
  translate: t,
  onStartTotpSetup,
  onConfirmTotpSetup,
  onRotateRecoveryCodes,
  onDisableMfa,
  onTotpSetupCodeChange,
  onPasskeyNameChange,
  onRegisterPasskey,
  onDeletePasskey,
  onRevokeSession,
  onRevokeConsent
}: AccountWorkspaceProps) {
  return (
    <section className="account-layout">
      <div className="client-list">
        <div className="panel">
          <h3>{t("account")}</h3>
          <div className="detail-grid">
            <div className="info-cell"><span>{t("email")}</span><strong>{user.email}</strong></div>
            <div className="info-cell"><span>{t("username")}</span><strong>{user.username}</strong></div>
            <div className="info-cell"><span>{t("displayName")}</span><strong>{user.display_name ?? "-"}</strong></div>
            <div className="info-cell"><span>{t("phone")}</span><strong>{user.phone ?? "-"}</strong></div>
            <div className="info-cell"><span>{t("role")}</span><strong>{user.is_admin ? t("admin") : t("normalUser")}</strong></div>
            <div className="info-cell"><span>{t("status")}</span><strong>{user.archived_at ? t("archived") : user.is_active ? t("active") : t("disabled")}</strong></div>
            <div className="info-cell"><span>{t("registeredAt")}</span><strong>{formatTime(user.created_at, locale)}</strong></div>
            <div className="info-cell"><span>{t("lastLogin")}</span><strong>{formatTime(user.last_login_at, locale)}</strong></div>
            <div className="info-cell"><span>{t("lastIp")}</span><strong>{user.last_login_ip ?? "-"}</strong></div>
            <div className="info-cell"><span>{t("lastClient")}</span><strong>{user.last_oidc_client_id ?? "-"}</strong></div>
          </div>
          {user.archived_at && <p className="muted">{t("archivedReadOnly")}</p>}
        </div>
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
      </div>
      <div className="client-list">
        <div className="table-panel">
          <h3>{t("activeSessions")}</h3>
          <table>
            <thead><tr><th>{t("sessionId")}</th><th>{t("device")}</th><th>{t("authMethod")}</th><th>{t("createdAt")}</th><th>{t("expiresAt")}</th><th></th></tr></thead>
            <tbody>
              {mySessions.map((session) => (
                <tr key={session.id}>
                  <td><code>{shortSessionId(session.id)}</code>{session.current && <><br /><small>{t("currentSession")}</small></>}</td>
                  <td><div className="session-device"><strong>{session.ip_address ?? "-"}</strong><small>{session.user_agent ?? "-"}</small></div></td>
                  <td>{session.login_method ?? "-"}</td>
                  <td>{formatTime(session.created_at, locale)}</td>
                  <td>{formatTime(session.expires_at, locale)}</td>
                  <td className="actions">
                    {canMutateAccount && !session.current && <button type="button" onClick={() => onRevokeSession(session.id)} disabled={busy}><LogOut size={14} />{t("revokeSession")}</button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {mySessions.length === 0 && <div className="empty">{t("noActiveSessions")}</div>}
        </div>
        <div className="table-panel">
          <h3>{t("authorizedApplications")}</h3>
          <table>
            <thead><tr><th>{t("clientName")}</th><th>{t("grantedScopes")}</th><th>{t("grantedAt")}</th><th>{t("updatedAt")}</th><th></th></tr></thead>
            <tbody>
              {myConsents.map((consent) => (
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
          {myConsents.length === 0 && <div className="empty">{t("noAuthorizedApplications")}</div>}
        </div>
      </div>
    </section>
  );
}
