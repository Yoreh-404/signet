import { useAuthVerificationActions } from "./use-auth-verification-actions";
import { useAuthorizationCodeLogin } from "./use-authorization-code-login";
import { usePasskeyLogin } from "./use-passkey-login";
import { usePasswordLogin } from "./use-password-login";
import { useRegistrationSubmit } from "./use-registration-submit";

type VerificationOptions = Parameters<typeof useAuthVerificationActions>[0];
type PasskeyOptions = Parameters<typeof usePasskeyLogin>[0];
type AuthorizationCodeOptions = Parameters<typeof useAuthorizationCodeLogin>[0];
type PasswordOptions = Parameters<typeof usePasswordLogin>[0];
type RegistrationOptions = Parameters<typeof useRegistrationSubmit>[0];

type Options = {
  verification: VerificationOptions;
  passkey: PasskeyOptions;
  authorizationCode: AuthorizationCodeOptions;
  password: PasswordOptions;
  registration: RegistrationOptions;
};

export function useAuthWorkspaceFacade(options: Options) {
  const verification = useAuthVerificationActions(options.verification);
  const passkey = usePasskeyLogin(options.passkey);
  const authorizationCode = useAuthorizationCodeLogin(options.authorizationCode);
  const password = usePasswordLogin(options.password);
  const registration = useRegistrationSubmit(options.registration);

  return { verification, passkey, authorizationCode, password, registration };
}
