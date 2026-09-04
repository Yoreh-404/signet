import type { ApplicationProfileRole } from "../../lib/api/application-authorization";

type ApplicationRoleSelectionListProps = {
  className: string;
  roles: ApplicationProfileRole[];
  selectedRoleIds: Set<string>;
  noDescriptionLabel: string;
  emptyLabel?: string;
  disabled: boolean;
  onToggle: (roleId: string) => void;
};

export function ApplicationRoleSelectionList({
  className,
  roles,
  selectedRoleIds,
  noDescriptionLabel,
  emptyLabel,
  disabled,
  onToggle,
}: ApplicationRoleSelectionListProps) {
  return (
    <div className={className}>
      {roles.map((role) => (
        <label className="application-choice" key={role.id}>
          <input
            type="checkbox"
            checked={selectedRoleIds.has(role.id)}
            onChange={() => onToggle(role.id)}
            disabled={disabled}
          />
          <span>
            <strong>{role.name}</strong>
            <small>{role.description || noDescriptionLabel}</small>
          </span>
        </label>
      ))}
      {roles.length === 0 && emptyLabel && (
        <p className="muted">{emptyLabel}</p>
      )}
    </div>
  );
}
