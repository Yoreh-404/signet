import { ArrowRight } from "lucide-react";
import type { ReactNode } from "react";

export type ModuleCopy = {
  save: string;
  saving: string;
  saveFailed: string;
};

export function ModuleHeader({
  icon,
  title,
  description
}: {
  icon: ReactNode;
  title: string;
  description: string;
}) {
  return (
    <div className="application-module-header">
      <span className="module-heading-icon">{icon}</span>
      <div>
        <h5>{title}</h5>
        <p>{description}</p>
      </div>
    </div>
  );
}

export function ModuleSave({
  saving,
  feedback,
  copy,
  onSave
}: {
  saving: boolean;
  feedback: string;
  copy: ModuleCopy;
  onSave: () => void;
}) {
  return (
    <div className="application-module-actions">
      <span className={feedback === copy.saveFailed ? "module-save-error" : "module-save-feedback"}>
        {feedback}
      </span>
      <button type="button" className="primary-action" onClick={onSave} disabled={saving}>
        {saving ? copy.saving : copy.save}
        <ArrowRight size={15} />
      </button>
    </div>
  );
}

export function Toggle({
  label,
  hint,
  checked,
  onChange,
  compact = false,
  disabled = false
}: {
  label?: string;
  hint?: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  compact?: boolean;
  disabled?: boolean;
}) {
  return (
    <label className={`application-toggle${compact ? " compact" : ""}`}>
      <span className="toggle-copy">
        {label && <strong>{label}</strong>}
        {hint && <small>{hint}</small>}
      </span>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span className="toggle-track" aria-hidden="true"><span /></span>
    </label>
  );
}

export function Input({
  label,
  hint,
  value,
  onChange,
  type = "text",
  textarea = false,
  disabled = false,
  required = false
}: {
  label: string;
  hint?: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  textarea?: boolean;
  disabled?: boolean;
  required?: boolean;
}) {
  return (
    <label className="application-input">
      <span>{label}</span>
      {textarea ? (
        <textarea
          value={value}
          disabled={disabled}
          required={required}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <input
          type={type}
          value={value}
          disabled={disabled}
          required={required}
          onChange={(event) => onChange(event.target.value)}
        />
      )}
      {hint && <small>{hint}</small>}
    </label>
  );
}

export function ProtocolCard({
  icon,
  title,
  description,
  enabled,
  onToggle,
  tone,
  children
}: {
  icon: ReactNode;
  title: string;
  description: string;
  enabled: boolean;
  onToggle: (value: boolean) => void;
  tone?: string;
  children: ReactNode;
}) {
  return (
    <article className={`protocol-card${tone ? ` protocol-${tone}` : ""}${enabled ? " enabled" : ""}`}>
      <div className="protocol-card-heading">
        <span className="protocol-icon">{icon}</span>
        <div>
          <h6>{title}</h6>
          <p>{description}</p>
        </div>
        <Toggle compact checked={enabled} onChange={onToggle} />
      </div>
      <div className="protocol-card-body">{children}</div>
    </article>
  );
}
