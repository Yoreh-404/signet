type LoginChallengeSetters = {
  setMfaChallengeId: (value: string) => void;
  setMfaCode: (value: string) => void;
  setRecoveryAvailable: (value: boolean) => void;
  setCaptchaChallengeId: (value: string) => void;
  setCaptchaPrompt: (value: string) => void;
  setCaptchaAnswer: (value: string) => void;
};

export function clearLoginChallengeState({
  setMfaChallengeId,
  setMfaCode,
  setRecoveryAvailable,
  setCaptchaChallengeId,
  setCaptchaPrompt,
  setCaptchaAnswer
}: LoginChallengeSetters) {
  setMfaChallengeId("");
  setMfaCode("");
  setRecoveryAvailable(false);
  setCaptchaChallengeId("");
  setCaptchaPrompt("");
  setCaptchaAnswer("");
}
