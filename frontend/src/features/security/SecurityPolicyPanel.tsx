import { Shield } from "lucide-react";

import { Check, Field, FormActions, ListField } from "../../components/ui";
import type { TranslationKey } from "../../i18n";
import { normalizeDomain } from "../../lib/auth-flow";
import { joinList, splitList } from "../../lib/formatters";
import type { SecurityPolicy } from "../../types";

export type SecurityPolicyPanelProps = {
  policy: SecurityPolicy;
  busy: boolean;
  dirty: boolean;
  translate: (key: TranslationKey) => string;
  onChange: (policy: SecurityPolicy) => void;
  onSubmit: (event: React.FormEvent<HTMLFormElement>) => void | Promise<void>;
};

export function SecurityPolicyPanel({
  policy,
  busy,
  dirty,
  translate: t,
  onChange,
  onSubmit
}: SecurityPolicyPanelProps) {
  return (
    <form className="panel security-policy-panel" onSubmit={onSubmit}>
      <div className="security-policy-header">
        <div className="security-card-title">
          <span className="security-card-icon" aria-hidden="true"><Shield size={18} /></span>
          <div>
            <h3>{t("securityPolicy")}</h3>
            <p>{t("passwordPolicy")} · {t("accessRiskRules")}</p>
          </div>
        </div>
        <span className="security-policy-status" aria-live="polite">
          {dirty ? t("unsavedChanges") : t("changesSaved")}
        </span>
      </div>
      <div className="security-policy-sections">
        <section className="security-policy-section" aria-labelledby="security-password-policy-heading">
          <h4 id="security-password-policy-heading">{t("passwordPolicy")}</h4>
          <Field
            label={t("minPasswordLength")}
            type="number"
            value={String(policy.password_min_length)}
            onChange={(value) => onChange({ ...policy, password_min_length: Number(value) })}
          />
          <div className="security-check-grid">
            <Check label={t("requireUppercase")} checked={Boolean(policy.password_require_uppercase)} onChange={(value) => onChange({ ...policy, password_require_uppercase: value ? 1 : 0 })} />
            <Check label={t("requireLowercase")} checked={Boolean(policy.password_require_lowercase)} onChange={(value) => onChange({ ...policy, password_require_lowercase: value ? 1 : 0 })} />
            <Check label={t("requireDigit")} checked={Boolean(policy.password_require_digit)} onChange={(value) => onChange({ ...policy, password_require_digit: value ? 1 : 0 })} />
            <Check label={t("requireSymbol")} checked={Boolean(policy.password_require_symbol)} onChange={(value) => onChange({ ...policy, password_require_symbol: value ? 1 : 0 })} />
            <Check label={t("rejectUserInfo")} checked={Boolean(policy.password_reject_user_info)} onChange={(value) => onChange({ ...policy, password_reject_user_info: value ? 1 : 0 })} />
          </div>
        </section>

        <section className="security-policy-section" aria-labelledby="security-login-protection-heading">
          <h4 id="security-login-protection-heading">{t("loginLockout")}</h4>
          <Check label={t("active")} checked={Boolean(policy.login_lockout_enabled)} onChange={(value) => onChange({ ...policy, login_lockout_enabled: value ? 1 : 0 })} />
          <div className="security-field-grid security-compact-fields">
            <Field
              label={t("maxFailedAttempts")}
              type="number"
              value={String(policy.max_failed_login_attempts)}
              onChange={(value) => onChange({ ...policy, max_failed_login_attempts: Number(value) })}
            />
            <Field
              label={t("failureWindowSeconds")}
              type="number"
              value={String(policy.failure_window_seconds)}
              onChange={(value) => onChange({ ...policy, failure_window_seconds: Number(value) })}
            />
            <Field
              label={t("lockoutSeconds")}
              type="number"
              value={String(policy.lockout_seconds)}
              onChange={(value) => onChange({ ...policy, lockout_seconds: Number(value) })}
            />
          </div>
          <div className="security-policy-subsection">
            <h5>{t("captchaPolicy")}</h5>
            <Check
              label={t("active")}
              checked={policy.captcha_enabled}
              onChange={(value) => onChange({ ...policy, captcha_enabled: value })}
            />
            <div className="security-field-grid">
              <Field
                label={t("captchaAfterFailedAttempts")}
                type="number"
                value={String(policy.captcha_after_failed_attempts)}
                onChange={(value) => onChange({ ...policy, captcha_after_failed_attempts: Number(value) })}
              />
              <Field
                label={t("captchaTtlSeconds")}
                type="number"
                value={String(policy.captcha_ttl_seconds)}
                onChange={(value) => onChange({ ...policy, captcha_ttl_seconds: Number(value) })}
              />
            </div>
          </div>
        </section>

        <section className="security-policy-section security-policy-section-wide" aria-labelledby="security-trusted-networks-heading">
          <h4 id="security-trusted-networks-heading">{t("trustedNetworks")}</h4>
          <div className="security-network-grid">
            <ListField
              label={t("trustedIpCidrs")}
              value={joinList(policy.trusted_ip_cidrs)}
              onChange={(value) => onChange({ ...policy, trusted_ip_cidrs: splitList(value) })}
              addLabel={t("addItem")}
              removeLabel={t("removeItem")}
            />
            <div className="security-network-option">
              <Check
                label={t("requireMfaOutsideTrustedNetworks")}
                checked={policy.require_mfa_outside_trusted_networks}
                onChange={(value) => onChange({ ...policy, require_mfa_outside_trusted_networks: value })}
              />
            </div>
          </div>
        </section>

        <section className="security-policy-section security-policy-section-wide" aria-labelledby="security-risk-rules-heading">
          <h4 id="security-risk-rules-heading">{t("accessRiskRules")}</h4>
          <div className="security-risk-grid">
            <ListField
              label={t("allowedIpCidrs")}
              value={joinList(policy.allowed_ip_cidrs)}
              onChange={(value) => onChange({ ...policy, allowed_ip_cidrs: splitList(value) })}
              addLabel={t("addItem")}
              removeLabel={t("removeItem")}
            />
            <ListField
              label={t("blockedIpCidrs")}
              value={joinList(policy.blocked_ip_cidrs)}
              onChange={(value) => onChange({ ...policy, blocked_ip_cidrs: splitList(value) })}
              addLabel={t("addItem")}
              removeLabel={t("removeItem")}
            />
            <ListField
              label={t("allowedEmailDomains")}
              value={joinList(policy.allowed_email_domains)}
              onChange={(value) => onChange({ ...policy, allowed_email_domains: splitList(value).map(normalizeDomain) })}
              addLabel={t("addItem")}
              removeLabel={t("removeItem")}
            />
            <ListField
              label={t("blockedEmailDomains")}
              value={joinList(policy.blocked_email_domains)}
              onChange={(value) => onChange({ ...policy, blocked_email_domains: splitList(value).map(normalizeDomain) })}
              addLabel={t("addItem")}
              removeLabel={t("removeItem")}
            />
          </div>
        </section>
      </div>
      <FormActions
        className="security-form-actions"
        submitLabel={t("save")}
        busy={busy}
        dirty={dirty}
        statusLabel={dirty ? t("unsavedChanges") : undefined}
        savingLabel={t("saving")}
      />
    </form>
  );
}
