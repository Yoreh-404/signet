import { ArrowRight } from "lucide-react";
import type { FormEvent } from "react";
import type {
  ApplicationOidcClientsCopy,
  OidcClientDraft,
} from "./ApplicationOidcClients";
import { Input, Toggle } from "./components/ApplicationModulePrimitives";

type ApplicationOidcClientEditorProps = {
  copy: ApplicationOidcClientsCopy;
  draft: OidcClientDraft;
  saving: boolean;
  onChange: (next: Partial<OidcClientDraft>) => void;
  onDiscard: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
};

export function ApplicationOidcClientEditor({
  copy,
  draft,
  saving,
  onChange,
  onDiscard,
  onSubmit,
}: ApplicationOidcClientEditorProps) {
  return (
    <form className="application-client-editor" onSubmit={onSubmit}>
      <div className="form-grid-2 compact-form-grid">
        <Input
          label={copy.clientId}
          value={draft.client_id}
          required
          onChange={(value) => onChange({ client_id: value })}
        />
        <Input
          label={copy.clientName}
          value={draft.client_name}
          required
          onChange={(value) => onChange({ client_name: value })}
        />
        <Input
          label={copy.clientSecret}
          hint={copy.clientSecretHint}
          type="password"
          value={draft.client_secret}
          required={!draft.id && draft.token_endpoint_auth_method !== "none"}
          onChange={(value) => onChange({ client_secret: value })}
        />
        <Input
          label={copy.audience}
          value={draft.audience}
          onChange={(value) => onChange({ audience: value })}
        />
      </div>
      <Input
        label={copy.redirectUris}
        value={draft.redirect_uris}
        textarea
        required
        onChange={(value) => onChange({ redirect_uris: value })}
      />
      <Input
        label={copy.postLogoutUris}
        value={draft.post_logout_redirect_uris}
        textarea
        onChange={(value) => onChange({ post_logout_redirect_uris: value })}
      />
      <div className="form-grid-2 compact-form-grid">
        <Input
          label={copy.scopes}
          value={draft.scopes}
          onChange={(value) => onChange({ scopes: value })}
        />
        <Input
          label={copy.grantTypes}
          value={draft.grant_types}
          onChange={(value) => onChange({ grant_types: value })}
        />
        <Input
          label={copy.responseTypes}
          value={draft.response_types}
          onChange={(value) => onChange({ response_types: value })}
        />
        <label className="application-input">
          <span>{copy.tokenAuthMethod}</span>
          <select
            value={draft.token_endpoint_auth_method}
            onChange={(event) =>
              onChange({ token_endpoint_auth_method: event.target.value })
            }
          >
            <option value="client_secret_basic">client_secret_basic</option>
            <option value="client_secret_post">client_secret_post</option>
            <option value="client_secret_jwt">client_secret_jwt</option>
            <option value="private_key_jwt">private_key_jwt</option>
            <option value="none">none</option>
          </select>
        </label>
      </div>
      <div className="application-toggle-grid">
        <Toggle
          label={copy.requirePkce}
          checked={draft.require_pkce}
          onChange={(value) =>
            onChange({
              require_pkce: value,
              require_s256_pkce: value ? draft.require_s256_pkce : false,
            })
          }
        />
        <Toggle
          label="S256 PKCE"
          checked={draft.require_s256_pkce}
          onChange={(value) =>
            onChange({
              require_s256_pkce: value,
              require_pkce: value || draft.require_pkce,
            })
          }
        />
        <Toggle
          label={copy.requireMfa}
          checked={draft.require_mfa}
          onChange={(value) => onChange({ require_mfa: value })}
        />
        <Toggle
          label={copy.active}
          checked={draft.is_active}
          onChange={(value) => onChange({ is_active: value })}
        />
      </div>
      <div className="application-module-actions">
        <button
          type="button"
          className="secondary-button"
          onClick={onDiscard}
          disabled={saving}
        >
          {copy.discardChanges}
        </button>
        <button type="submit" className="primary-action" disabled={saving}>
          {saving ? copy.saving : copy.save}
          <ArrowRight size={15} />
        </button>
      </div>
    </form>
  );
}
