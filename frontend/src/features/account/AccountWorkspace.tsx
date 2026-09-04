import { Ban } from "lucide-react";
import { memo } from "react";

import type { TranslationKey } from "../../i18n";
import type { Locale, MfaStatus, MyConsent, MySession, Passkey, TotpSetup, User } from "../../types";
import { ConsentListPanel } from "./ConsentListPanel";
import { PasskeyPanel } from "./PasskeyPanel";
import { ProfilePanel } from "./ProfilePanel";
import { SecurityMfaPanel } from "./SecurityMfaPanel";
import { SessionListPanel } from "./SessionListPanel";

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
  hasMoreSessions: boolean;
  loadingMoreSessions: boolean;
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
  onLoadMoreSessions: () => void | Promise<void>;
  onRevokeConsent: (clientId: string) => void | Promise<void>;
};

export const AccountWorkspace = memo(function AccountWorkspace({
  user,
  locale,
  mfaStatus,
  totpSetup,
  totpSetupCode,
  recoveryCodes,
  passkeyName,
  passkeys,
  mySessions,
  hasMoreSessions,
  loadingMoreSessions,
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
  onLoadMoreSessions,
  onRevokeConsent
}: AccountWorkspaceProps) {
  return (
    <section className="account-layout">
      <div className="client-list">
        <ProfilePanel user={user} locale={locale} translate={t} />
        <SecurityMfaPanel
          mfaStatus={mfaStatus}
          totpSetup={totpSetup}
          totpSetupCode={totpSetupCode}
          recoveryCodes={recoveryCodes}
          busy={busy}
          canMutateAccount={canMutateAccount}
          translate={t}
          onStartTotpSetup={onStartTotpSetup}
          onConfirmTotpSetup={onConfirmTotpSetup}
          onRotateRecoveryCodes={onRotateRecoveryCodes}
          onDisableMfa={onDisableMfa}
          onTotpSetupCodeChange={onTotpSetupCodeChange}
        />
        <PasskeyPanel
          locale={locale}
          passkeyName={passkeyName}
          passkeys={passkeys}
          busy={busy}
          canMutateAccount={canMutateAccount}
          translate={t}
          onPasskeyNameChange={onPasskeyNameChange}
          onRegisterPasskey={onRegisterPasskey}
          onDeletePasskey={onDeletePasskey}
        />
      </div>
      <div className="client-list">
        <SessionListPanel
          locale={locale}
          sessions={mySessions}
          hasMore={hasMoreSessions}
          loadingMore={loadingMoreSessions}
          busy={busy}
          canMutateAccount={canMutateAccount}
          translate={t}
          onRevokeSession={onRevokeSession}
          onLoadMore={onLoadMoreSessions}
        />
        <ConsentListPanel
          locale={locale}
          consents={myConsents}
          busy={busy}
          canMutateAccount={canMutateAccount}
          translate={t}
          onRevokeConsent={onRevokeConsent}
        />
      </div>
    </section>
  );
});
