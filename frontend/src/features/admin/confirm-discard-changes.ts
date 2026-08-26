import type { TranslationKey } from "../../i18n";

export function confirmDiscardChanges(translate: (key: TranslationKey) => string): boolean {
  return window.confirm(`${translate("unsavedChanges")}\n${translate("discardChanges")}?`);
}
