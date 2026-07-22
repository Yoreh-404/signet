import type { FormEvent } from "react";
import type { LoginMethod } from "../types";
import { Field } from "./ui";

export function LoginMethodSwitcher({
  value,
  onChange,
  disabled,
  label,
  passwordLabel,
  authorizationCodeLabel
}: {
  value: LoginMethod;
  onChange: (value: LoginMethod) => void;
  disabled: boolean;
  label: string;
  passwordLabel: string;
  authorizationCodeLabel: string;
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      <button
        type="button"
        className={value === "password" ? "active" : ""}
        aria-pressed={value === "password"}
        disabled={disabled}
        onClick={() => onChange("password")}
      >
        {passwordLabel}
      </button>
      <button
        type="button"
        className={value === "authorization_code" ? "active" : ""}
        aria-pressed={value === "authorization_code"}
        disabled={disabled}
        onClick={() => onChange("authorization_code")}
      >
        {authorizationCodeLabel}
      </button>
    </div>
  );
}

export function AuthorizationCodeLoginForm({
  email,
  authorizationCode,
  onAuthorizationCodeChange,
  onEmailChange,
  onSubmit,
  busy,
  emailLabel,
  authorizationCodeLabel,
  hint,
  submitLabel
}: {
  email: string;
  authorizationCode: string;
  onAuthorizationCodeChange: (value: string) => void;
  onEmailChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  busy: boolean;
  emailLabel: string;
  authorizationCodeLabel: string;
  hint: string;
  submitLabel: string;
}) {
  return (
    <form aria-busy={busy} onSubmit={onSubmit}>
      <Field
        label={emailLabel}
        value={email}
        onChange={onEmailChange}
        type="email"
        autoComplete="email"
        autoCapitalize="none"
        spellCheck={false}
        required
      />
      <Field
        label={authorizationCodeLabel}
        value={authorizationCode}
        onChange={onAuthorizationCodeChange}
        type="password"
        autoComplete="one-time-code"
        autoCapitalize="none"
        spellCheck={false}
        required
        description={hint}
      />
      <button className="primary" type="submit" disabled={busy}>
        {submitLabel}
      </button>
    </form>
  );
}
