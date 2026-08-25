import { useState } from "react";
import { emptyApplicationForm } from "../../lib/form-defaults";

/** Owns the application create/edit draft used by the admin shell. */
export function useApplicationController() {
  const [applicationForm, setApplicationForm] = useState(emptyApplicationForm);
  const [applicationFormBaseline, setApplicationFormBaseline] = useState<typeof emptyApplicationForm | null>(null);

  return {
    applicationForm,
    setApplicationForm,
    applicationFormBaseline,
    setApplicationFormBaseline
  };
}

export type ApplicationController = ReturnType<typeof useApplicationController>;

