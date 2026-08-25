import { useState } from "react";
import { emptyInvitationForm } from "../../lib/form-defaults";
import type { Invitation } from "../../types";

/** Owns invitation drafts and the one-time code reveal lifecycle. */
export function useInvitationController() {
  const [invitationForm, setInvitationForm] = useState(emptyInvitationForm);
  const [invitationFormBaseline, setInvitationFormBaseline] = useState<typeof emptyInvitationForm | null>(null);
  const [revealedInvitation, setRevealedInvitation] = useState<Invitation | null>(null);
  const [revealedInvitationCode, setRevealedInvitationCode] = useState("");
  const [revealingInvitationId, setRevealingInvitationId] = useState("");
  const [invitationRevealError, setInvitationRevealError] = useState("");

  return {
    invitationForm,
    setInvitationForm,
    invitationFormBaseline,
    setInvitationFormBaseline,
    revealedInvitation,
    setRevealedInvitation,
    revealedInvitationCode,
    setRevealedInvitationCode,
    revealingInvitationId,
    setRevealingInvitationId,
    invitationRevealError,
    setInvitationRevealError
  };
}

export type InvitationController = ReturnType<typeof useInvitationController>;

