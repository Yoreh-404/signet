import { ChevronDown, ChevronUp, Eye, EyeOff, Plus, Search, X } from "lucide-react";
import {
  ComponentPropsWithoutRef,
  FormEvent,
  ReactNode,
  useEffect,
  useId,
  useRef,
  useState
} from "react";

export function Card({
  children,
  className = "",
  as: Component = "div",
  ...props
}: ComponentPropsWithoutRef<"div"> & { as?: "div" | "article" | "section" }) {
  return (
    <Component {...props} className={`card ${className}`.trim()}>
      {children}
    </Component>
  );
}

type FieldProps = {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  textarea?: boolean;
  placeholder?: string;
  autoComplete?: string;
  autoCapitalize?: string;
  spellCheck?: boolean;
  min?: string | number;
  step?: string | number;
  required?: boolean;
  disabled?: boolean;
  description?: string;
};

export function Field({
  label,
  value,
  onChange,
  type = "text",
  textarea = false,
  placeholder,
  autoComplete,
  autoCapitalize,
  spellCheck,
  min,
  step,
  required,
  disabled,
  description
}: FieldProps) {
  const id = useId();
  const descriptionId = description ? `${id}-description` : undefined;
  const common = {
    id,
    value,
    placeholder,
    required,
    disabled,
    "aria-describedby": descriptionId,
    onChange: (event: FormEvent<HTMLInputElement | HTMLTextAreaElement>) =>
      onChange(event.currentTarget.value)
  };

  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {textarea ? (
        <textarea {...common} />
      ) : (
        <input
          {...common}
          type={type}
          autoComplete={autoComplete}
          autoCapitalize={autoCapitalize}
          spellCheck={spellCheck}
          min={min}
          step={step}
        />
      )}
      {description && <small id={descriptionId} className="field-description">{description}</small>}
    </div>
  );
}

export function SelectField({
  label,
  value,
  onChange,
  children,
  disabled = false,
  description
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  children: ReactNode;
  disabled?: boolean;
  description?: string;
}) {
  const id = useId();
  const descriptionId = description ? `${id}-description` : undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        aria-describedby={descriptionId}
        onChange={(event) => onChange(event.target.value)}
      >
        {children}
      </select>
      {description && <small id={descriptionId} className="field-description">{description}</small>}
    </div>
  );
}

export function Check({
  label,
  checked,
  onChange,
  disabled = false
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className="check">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
      <span>{label}</span>
    </label>
  );
}

/**
 * A compact section primitive for long configuration forms.  The content is
 * kept in the DOM while collapsed so browser validation and screen-reader
 * navigation remain predictable when a section is reopened.
 */
export function SettingsSection({
  title,
  description,
  children,
  defaultOpen = true,
  collapsible = true,
  className = ""
}: {
  title: string;
  description?: string;
  children: ReactNode;
  defaultOpen?: boolean;
  collapsible?: boolean;
  className?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const headingId = useId();

  return (
    <section className={`settings-section ${open ? "is-open" : "is-collapsed"} ${className}`.trim()}>
      {collapsible ? (
        <button
          type="button"
          className="settings-section-toggle"
          aria-expanded={open}
          aria-controls={`${headingId}-content`}
          onClick={() => setOpen((current) => !current)}
        >
          <span>
            <strong id={headingId}>{title}</strong>
            {description && <small>{description}</small>}
          </span>
          {open ? <ChevronUp size={17} aria-hidden="true" /> : <ChevronDown size={17} aria-hidden="true" />}
        </button>
      ) : (
        <div className="settings-section-heading">
          <strong id={headingId}>{title}</strong>
          {description && <small>{description}</small>}
        </div>
      )}
      <div id={`${headingId}-content`} className="settings-section-content" hidden={!open}>
        {children}
      </div>
    </section>
  );
}

export function FormActions({
  submitLabel,
  cancelLabel,
  onCancel,
  busy = false,
  dirty = false,
  statusLabel,
  savingLabel,
  className = ""
}: {
  submitLabel: string;
  cancelLabel?: string;
  onCancel?: () => void;
  busy?: boolean;
  dirty?: boolean;
  statusLabel?: string;
  savingLabel?: string;
  className?: string;
}) {
  return (
    <div className={`form-actions ${className}`.trim()}>
      <span className="form-actions-status" aria-live="polite">
        {statusLabel ?? (dirty ? "" : "")}
      </span>
      <div className="actions">
        {onCancel && cancelLabel && (
          <button type="button" onClick={onCancel} disabled={busy}>{cancelLabel}</button>
        )}
        <button className="primary" type="submit" disabled={busy}>
          {busy ? (savingLabel ?? submitLabel) : submitLabel}
        </button>
      </div>
    </div>
  );
}

export function SecretField({
  label,
  value,
  onChange,
  placeholder,
  autoComplete,
  required,
  disabled,
  description,
  revealLabel,
  hideLabel
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  autoComplete?: string;
  required?: boolean;
  disabled?: boolean;
  description?: string;
  revealLabel: string;
  hideLabel: string;
}) {
  const [revealed, setRevealed] = useState(false);
  const id = useId();
  const descriptionId = description ? `${id}-description` : undefined;

  return (
    <div className="field secret-field">
      <label htmlFor={id}>{label}</label>
      <div className="secret-input-row">
        <input
          id={id}
          type={revealed ? "text" : "password"}
          value={value}
          placeholder={placeholder}
          autoComplete={autoComplete}
          required={required}
          disabled={disabled}
          aria-describedby={descriptionId}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
        <button
          type="button"
          className="icon-button"
          aria-label={revealed ? hideLabel : revealLabel}
          title={revealed ? hideLabel : revealLabel}
          onClick={() => setRevealed((current) => !current)}
          disabled={disabled}
        >
          {revealed ? <EyeOff size={16} aria-hidden="true" /> : <Eye size={16} aria-hidden="true" />}
        </button>
      </div>
      {description && <small id={descriptionId} className="field-description">{description}</small>}
    </div>
  );
}

export function ListField({
  label,
  value,
  onChange,
  addLabel,
  removeLabel,
  placeholder,
  description,
  type = "text",
  disabled = false
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  addLabel: string;
  removeLabel: string;
  placeholder?: string;
  description?: string;
  type?: string;
  disabled?: boolean;
}) {
  const id = useId();
  const descriptionId = description ? `${id}-description` : undefined;
  const items = value === "" ? [""] : value.split(/\r?\n/);

  function updateItem(index: number, nextValue: string) {
    const next = items.map((item, itemIndex) => itemIndex === index ? nextValue : item);
    onChange(next.join("\n"));
  }

  function removeItem(index: number) {
    const next = items.filter((_, itemIndex) => itemIndex !== index);
    onChange(next.length > 0 ? next.join("\n") : "");
  }

  return (
    <div className="field list-field">
      <label id={`${id}-label`}>{label}</label>
      <div className="list-field-items" role="group" aria-labelledby={`${id}-label`} aria-describedby={descriptionId}>
        {items.map((item, index) => (
          <div className="list-field-row" key={`${id}-${index}`}>
            <input
              type={type}
              value={item}
              placeholder={placeholder}
              disabled={disabled}
              onChange={(event) => updateItem(index, event.currentTarget.value)}
            />
            <button
              type="button"
              className="icon-button list-field-remove"
              aria-label={`${removeLabel} ${index + 1}`}
              title={removeLabel}
              onClick={() => removeItem(index)}
              disabled={disabled || (items.length === 1 && item === "")}
            >
              <X size={15} aria-hidden="true" />
            </button>
          </div>
        ))}
      </div>
      <button type="button" className="list-field-add" onClick={() => onChange(`${value}\n`)} disabled={disabled}>
        <Plus size={14} aria-hidden="true" />
        {addLabel}
      </button>
      {description && <small id={descriptionId} className="field-description">{description}</small>}
    </div>
  );
}

export function FormErrorSummary({
  title,
  errors
}: {
  title: string;
  errors: string[];
}) {
  const visibleErrors = errors.filter(Boolean);
  if (visibleErrors.length === 0) return null;
  return (
    <div className="form-error-summary" role="alert" tabIndex={-1}>
      <strong>{title}</strong>
      <ul>
        {visibleErrors.map((error, index) => <li key={`${error}-${index}`}>{error}</li>)}
      </ul>
    </div>
  );
}

export function Modal({
  title,
  children,
  onClose,
  closeLabel,
  error,
  wide = false,
  dismissible = true,
  className = ""
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  closeLabel: string;
  error?: string;
  wide?: boolean;
  dismissible?: boolean;
  className?: string;
}) {
  const titleId = useId();
  const dialogRef = useRef<HTMLElement>(null);
  const onCloseRef = useRef(onClose);
  const dismissibleRef = useRef(dismissible);
  onCloseRef.current = onClose;
  dismissibleRef.current = dismissible;

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const focusable = focusableElements(dialogRef.current);
    (focusable[0] ?? dialogRef.current)?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && dismissibleRef.current) {
        event.preventDefault();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const elements = focusableElements(dialogRef.current);
      if (elements.length === 0) {
        event.preventDefault();
        dialogRef.current?.focus();
        return;
      }
      const first = elements[0];
      const last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, []);

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (dismissible && event.currentTarget === event.target) onClose();
      }}
    >
      <section
        ref={dialogRef}
        className={`modal ${wide ? "modal-wide" : ""} ${className}`.trim()}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="modal-header">
          <h3 id={titleId}>{title}</h3>
          {dismissible && (
            <button type="button" aria-label={closeLabel} title={closeLabel} onClick={onClose}>
              <X size={18} />
            </button>
          )}
        </div>
        {error && <div className="error modal-error" role="alert">{error}</div>}
        {children}
      </section>
    </div>
  );
}

export function SearchField({
  value,
  onChange,
  placeholder,
  clearLabel
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  clearLabel: string;
}) {
  return (
    <label className="search-control">
      <Search size={16} aria-hidden="true" />
      <span className="sr-only">{placeholder}</span>
      <input
        type="search"
        value={value}
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
      />
      {value && (
        <button type="button" onClick={() => onChange("")} aria-label={clearLabel} title={clearLabel}>
          <X size={15} />
        </button>
      )}
    </label>
  );
}

export function EmptyState({
  title,
  description,
  icon,
  action
}: {
  title: string;
  description?: string;
  icon?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty-state">
      {icon && <span className="empty-state-icon">{icon}</span>}
      <strong>{title}</strong>
      {description && <p>{description}</p>}
      {action}
    </div>
  );
}

export function StatusBadge({
  tone,
  children
}: {
  tone: "success" | "warning" | "danger" | "neutral" | "info";
  children: ReactNode;
}) {
  return <span className={`status-badge status-${tone}`}>{children}</span>;
}

function focusableElements(container: HTMLElement | null): HTMLElement[] {
  if (!container) return [];
  return Array.from(container.querySelectorAll<HTMLElement>(
    'a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
  )).filter((element) => (
    !element.hasAttribute("hidden")
    && element.getClientRects().length > 0
    && window.getComputedStyle(element).visibility !== "hidden"
  ));
}
