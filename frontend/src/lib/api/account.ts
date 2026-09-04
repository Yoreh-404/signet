import { pathSegment, requestJson, requestJsonWithResponse, writeJson } from "./transport";
import type { ApiMutationOptions } from "./transport";
import type {
  MfaConfirmResponse,
  MfaStatus,
  MyConsent,
  MySession,
  Passkey,
  PasskeyAuthenticationStart,
  PasskeyRegistrationStart,
  TotpSetup
} from "../../types";

type ReadOptions = Pick<ApiMutationOptions, "signal">;

const ACCOUNT = "/api";

export function getMfaStatus(options: ReadOptions = {}): Promise<MfaStatus> {
  return requestJson<MfaStatus>(`${ACCOUNT}/mfa/status`, options);
}

export function startTotpSetup(): Promise<TotpSetup> {
  return writeJson<TotpSetup, undefined>(`${ACCOUNT}/mfa/totp`, "POST", undefined);
}

export function confirmTotpSetup(setupId: string, code: string): Promise<MfaConfirmResponse> {
  return writeJson<MfaConfirmResponse, { setup_id: string; code: string }>(
    `${ACCOUNT}/mfa/totp/confirm`,
    "POST",
    { setup_id: setupId, code }
  );
}

export function rotateRecoveryCodes(): Promise<MfaConfirmResponse> {
  return writeJson<MfaConfirmResponse, undefined>(`${ACCOUNT}/mfa/recovery-codes/rotate`, "POST", undefined);
}

export function disableMfa(): Promise<MfaStatus> {
  return writeJson<MfaStatus, undefined>(`${ACCOUNT}/mfa/totp`, "DELETE", undefined);
}

export function listPasskeys(options: ReadOptions = {}): Promise<Passkey[]> {
  return requestJson<Passkey[]>(`${ACCOUNT}/passkeys`, options);
}

export function startPasskeyRegistration(name: string | null): Promise<PasskeyRegistrationStart> {
  return writeJson<PasskeyRegistrationStart, { name: string | null }>(
    `${ACCOUNT}/passkeys/registration/start`,
    "POST",
    { name }
  );
}

export function finishPasskeyRegistration(input: {
  challengeId: string;
  name: string | null;
  credential: unknown;
}): Promise<Passkey> {
  return writeJson<Passkey, {
    challenge_id: string;
    name: string | null;
    credential: unknown;
  }>(`${ACCOUNT}/passkeys/registration/finish`, "POST", {
      challenge_id: input.challengeId,
      name: input.name,
      credential: input.credential
    });
}

export function deletePasskey(id: string): Promise<void> {
  return writeJson<void, undefined>(`${ACCOUNT}/passkeys/${pathSegment(id)}`, "DELETE", undefined);
}

export function startPasskeyAuthentication(
  email: string,
  accountFlow: string | null
): Promise<PasskeyAuthenticationStart> {
  return writeJson<PasskeyAuthenticationStart, { email: string; account_flow: string | null }>(
    `${ACCOUNT}/passkeys/authentication/start`,
    "POST",
    { email, account_flow: accountFlow }
  );
}

export function finishPasskeyAuthentication<T = unknown>(input: {
  challengeId: string;
  credential: unknown;
  accountFlow: string | null;
}): Promise<T> {
  return writeJson<T, {
    challenge_id: string;
    credential: unknown;
    account_flow: string | null;
  }>(`${ACCOUNT}/passkeys/authentication/finish`, "POST", {
      challenge_id: input.challengeId,
      credential: input.credential,
      account_flow: input.accountFlow
    });
}

export function listConsents(options: ReadOptions = {}): Promise<MyConsent[]> {
  return requestJson<MyConsent[]>(`${ACCOUNT}/me/consents`, options);
}

export function revokeConsent(clientId: string): Promise<void> {
  return writeJson<void, undefined>(`${ACCOUNT}/me/consents/${pathSegment(clientId)}`, "DELETE", undefined);
}

export function listSessions(options: ReadOptions = {}): Promise<MySession[]> {
  return listSessionsPage(options).then(({ sessions }) => sessions);
}

export type SessionListOptions = ReadOptions & {
  cursor?: string | null;
  limit?: number;
};

export type MySessionPage = {
  sessions: MySession[];
  nextCursor: string | null;
};

export function listSessionsPage(options: SessionListOptions = {}): Promise<MySessionPage> {
  const params = new URLSearchParams();
  if (options.limit !== undefined) params.set("limit", String(options.limit));
  if (options.cursor) params.set("cursor", options.cursor);
  const query = params.toString();
  return requestJsonWithResponse<MySession[]>(
    `${ACCOUNT}/me/sessions${query ? `?${query}` : ""}`,
    { signal: options.signal }
  ).then(({ value, headers }) => ({
    sessions: value,
    nextCursor: headers.get("x-next-cursor")
  }));
}

export function revokeSession(sessionId: string): Promise<void> {
  return writeJson<void, undefined>(`${ACCOUNT}/me/sessions/${pathSegment(sessionId)}`, "DELETE", undefined);
}
