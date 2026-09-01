import { useEffect, useState } from "react";

import { api } from "../../lib/api";
import type { AuthMode, AuthorizationCodeInspection } from "../../types";

type RegistrationCodeInspectionOptions = {
  hasUsers: boolean;
  authMode: AuthMode;
  authorizationCode: string;
};

export function useRegistrationCodeInspection({
  hasUsers,
  authMode,
  authorizationCode
}: RegistrationCodeInspectionOptions) {
  const [inspection, setInspection] = useState<AuthorizationCodeInspection | null>(null);
  const [inspecting, setInspecting] = useState(false);

  useEffect(() => {
    const normalizedCode = authorizationCode.trim();
    if (!hasUsers || authMode !== "register" || !normalizedCode) {
      setInspection(null);
      setInspecting(false);
      return;
    }

    let current = true;
    setInspection(null);
    setInspecting(true);
    const timer = window.setTimeout(() => {
      void api<AuthorizationCodeInspection>("/api/public/authorization-code/inspect", {
        method: "POST",
        body: JSON.stringify({ authorization_code: normalizedCode })
      }).then((nextInspection) => {
        if (current) setInspection(nextInspection);
      }).catch(() => {
        if (current) setInspection(null);
      }).finally(() => {
        if (current) setInspecting(false);
      });
    }, 350);

    return () => {
      current = false;
      window.clearTimeout(timer);
    };
  }, [authMode, authorizationCode, hasUsers]);

  return { inspection, inspecting };
}
