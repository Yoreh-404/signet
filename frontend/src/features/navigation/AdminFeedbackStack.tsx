import { Shield } from "lucide-react";

import type { TranslationKey } from "../../i18n";

type Translator = (key: TranslationKey) => string;

type AdminFeedbackStackProps = {
  loading: boolean;
  error: string;
  editorOpen: boolean;
  confirmationOpen: boolean;
  restrictedLoginCodeSession: boolean;
  trialEnrollmentSession: boolean;
  verificationMessage: string;
  t: Translator;
};

export function AdminFeedbackStack({
  loading,
  error,
  editorOpen,
  confirmationOpen,
  restrictedLoginCodeSession,
  trialEnrollmentSession,
  verificationMessage,
  t,
}: AdminFeedbackStackProps) {
  return (
    <>
      {loading && <div className="loading-bar" role="progressbar" aria-label={t("loading")} />}
      {error && !editorOpen && !confirmationOpen && <div className="error" role="alert">{error}</div>}
      {restrictedLoginCodeSession && (
        <div className="info temporary-session-banner" role="status" aria-live="polite">
          <Shield size={17} aria-hidden="true" />
          <span>{t(trialEnrollmentSession ? "trialEnrollmentAccountReady" : "temporaryAccountReady")}</span>
        </div>
      )}
      {verificationMessage && <div className="toast" role="status" aria-live="polite">{verificationMessage}</div>}
    </>
  );
}
