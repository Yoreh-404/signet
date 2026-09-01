import { AtSign } from "lucide-react";
import type { ReactNode } from "react";

import { applyEmailDomain, usableEmailDomain } from "../../lib/auth-flow";
import { Field } from "../../components/ui";

export function EmailField({
  label,
  value,
  onChange,
  domains,
  customDomain,
  onCustomDomainChange,
  customLabel,
  applyLabel,
  required = true
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  domains: string[];
  customDomain: string;
  onCustomDomainChange: (value: string) => void;
  customLabel: string;
  applyLabel: string;
  required?: boolean;
}) {
  const customSuffix = usableEmailDomain(customDomain);
  return (
    <div className="email-field">
      <Field label={label} value={value} onChange={onChange} type="email" autoComplete="email" required={required} />
      {domains.length > 0 && (
        <div className="domain-pills" role="group" aria-label={label}>
          {domains.map((domain) => (
            <button type="button" key={domain} onClick={() => onChange(applyEmailDomain(value, domain))}>
              @{domain}
            </button>
          ))}
        </div>
      )}
      <div className="custom-domain">
        <input aria-label={customLabel} autoComplete="off" value={customDomain} placeholder={customLabel} onChange={(event) => onCustomDomainChange(event.target.value)} />
        <button type="button" disabled={!customSuffix} onClick={() => onChange(applyEmailDomain(value, customSuffix))}>
          <AtSign size={14} />
          {applyLabel}
        </button>
      </div>
    </div>
  );
}

export function InlineCode({
  icon,
  label,
  button,
  value,
  onChange,
  onSend,
  disabled = false
}: {
  icon: ReactNode;
  label: string;
  button: string;
  value: string;
  onChange: (value: string) => void;
  onSend: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="inline-code">
      <Field label={label} value={value} onChange={onChange} autoComplete="one-time-code" />
      <button type="button" onClick={onSend} disabled={disabled}>{icon}{button}</button>
    </div>
  );
}
