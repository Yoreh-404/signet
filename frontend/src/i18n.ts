import { applicationsTranslations } from "./i18n/applications";
import { authTranslations } from "./i18n/auth";
import { billingTranslations } from "./i18n/billing";
import { clientsTranslations } from "./i18n/clients";
import { commonTranslations } from "./i18n/common";
import { errorsTranslations } from "./i18n/errors";
import { invitationsTranslations } from "./i18n/invitations";
import { navigationControlsTranslations } from "./i18n/navigation-controls";
import { navigationTranslations } from "./i18n/navigation";
import { providersTranslations } from "./i18n/providers";
import { securityTranslations } from "./i18n/security";
import { usersTranslations } from "./i18n/users";

export const translations = {
  "zh-CN": {
    ...authTranslations["zh-CN"],
    ...navigationTranslations["zh-CN"],
    ...billingTranslations["zh-CN"],
    ...navigationControlsTranslations["zh-CN"],
    ...applicationsTranslations["zh-CN"],
    ...commonTranslations["zh-CN"],
    ...usersTranslations["zh-CN"],
    ...clientsTranslations["zh-CN"],
    ...invitationsTranslations["zh-CN"],
    ...providersTranslations["zh-CN"],
    ...securityTranslations["zh-CN"],
    ...errorsTranslations["zh-CN"]
  },
  "en-US": {
    ...authTranslations["en-US"],
    ...navigationTranslations["en-US"],
    ...billingTranslations["en-US"],
    ...navigationControlsTranslations["en-US"],
    ...applicationsTranslations["en-US"],
    ...commonTranslations["en-US"],
    ...usersTranslations["en-US"],
    ...clientsTranslations["en-US"],
    ...invitationsTranslations["en-US"],
    ...providersTranslations["en-US"],
    ...securityTranslations["en-US"],
    ...errorsTranslations["en-US"]
  }
} as const;

export type TranslationKey = keyof typeof translations["zh-CN"] & keyof typeof translations["en-US"];
