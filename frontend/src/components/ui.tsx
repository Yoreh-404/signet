import { Search, X } from "lucide-react";
import {
  ComponentPropsWithoutRef,
  FormEvent,
  ReactNode,
  useEffect,
  useId,
  useRef
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
