import type {
  WebauthnCreationResponseJson,
  WebauthnRequestResponseJson
} from "../types";

function base64urlToBuffer(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function bufferSourceToBase64url(value: BufferSource | null): string | null {
  if (!value) return null;
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function passkeyCreationOptions(value: WebauthnCreationResponseJson): CredentialCreationOptions {
  const publicKey = value.publicKey;
  return {
    publicKey: {
      ...publicKey,
      challenge: base64urlToBuffer(publicKey.challenge),
      excludeCredentials: publicKey.excludeCredentials?.map((credential) => ({
        ...credential,
        id: base64urlToBuffer(credential.id)
      })),
      user: {
        ...publicKey.user,
        id: base64urlToBuffer(publicKey.user.id)
      }
    }
  };
}

export function passkeyRequestOptions(value: WebauthnRequestResponseJson): CredentialRequestOptions {
  const publicKey = value.publicKey;
  return {
    mediation: value.mediation,
    publicKey: {
      ...publicKey,
      allowCredentials: publicKey.allowCredentials?.map((credential) => ({
        ...credential,
        id: base64urlToBuffer(credential.id)
      })),
      challenge: base64urlToBuffer(publicKey.challenge)
    }
  };
}

export function registrationCredentialJson(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAttestationResponse & {
    getTransports?: () => AuthenticatorTransport[];
  };
  return {
    id: credential.id,
    rawId: bufferSourceToBase64url(credential.rawId),
    response: {
      attestationObject: bufferSourceToBase64url(response.attestationObject),
      clientDataJSON: bufferSourceToBase64url(response.clientDataJSON),
      transports: response.getTransports?.()
    },
    type: credential.type,
    extensions: credential.getClientExtensionResults()
  };
}

export function authenticationCredentialJson(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferSourceToBase64url(credential.rawId),
    response: {
      authenticatorData: bufferSourceToBase64url(response.authenticatorData),
      clientDataJSON: bufferSourceToBase64url(response.clientDataJSON),
      signature: bufferSourceToBase64url(response.signature),
      userHandle: bufferSourceToBase64url(response.userHandle)
    },
    type: credential.type,
    extensions: credential.getClientExtensionResults()
  };
}
