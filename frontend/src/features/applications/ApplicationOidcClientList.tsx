import { Pencil, Plus, Trash2 } from "lucide-react";
import type { ReactNode } from "react";
import type { Client } from "../../types";
import type { ApplicationOidcClientsCopy } from "./ApplicationOidcClients";

type ApplicationOidcClientListProps = {
  copy: ApplicationOidcClientsCopy;
  canManage: boolean;
  clients: Client[];
  saving: boolean;
  onCreate: () => void;
  onEdit: (client: Client) => void;
  onDelete: (client: Client) => void;
  children?: ReactNode;
};

export function ApplicationOidcClientList({
  copy,
  canManage,
  clients,
  saving,
  onCreate,
  onEdit,
  onDelete,
  children,
}: ApplicationOidcClientListProps) {
  return (
    <>
      <div className="subsection-heading">
        <div>
          <strong>{copy.oidcClients}</strong>
          <p className="muted">{copy.oidcClientHint}</p>
        </div>
        <button
          type="button"
          className="secondary-button"
          onClick={onCreate}
          disabled={!canManage || saving}
        >
          <Plus size={14} />
          {copy.createOidcClient}
        </button>
      </div>
      {children}
      <div className="application-oidc-client-cards">
        {clients.map((client) => (
          <article className="application-oidc-client-card" key={client.id}>
            <div className="application-oidc-client-card-heading">
              <div>
                <strong>{client.client_name}</strong>
                <small>
                  <code>{client.client_id}</code>
                </small>
              </div>
              <span className={`tab-status ${client.is_active ? "on" : ""}`}>
                {client.is_active ? copy.active : copy.disabled}
              </span>
            </div>
            <div className="tag-row">
              <span>{client.token_endpoint_auth_method}</span>
              {client.require_pkce && <span>{copy.requirePkce}</span>}
              <span>{client.scopes.join(" ")}</span>
            </div>
            <small>{client.redirect_uris.join(", ")}</small>
            {canManage && (
              <div className="actions">
                <button
                  type="button"
                  onClick={() => onEdit(client)}
                  disabled={saving}
                >
                  <Pencil size={14} />
                  {copy.edit}
                </button>
                <button
                  type="button"
                  className="text-danger-button"
                  onClick={() => onDelete(client)}
                  disabled={saving}
                >
                  <Trash2 size={14} />
                  {copy.delete}
                </button>
              </div>
            )}
          </article>
        ))}
        {clients.length === 0 && <p className="muted">{copy.noConnections}</p>}
      </div>
    </>
  );
}
