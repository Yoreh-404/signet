import { Plus, RefreshCw } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { TranslationKey } from "../../i18n";
import type {
  BrowserAccount,
  BrowserAccountAddResponse,
  BrowserAccountSelectionResponse,
  BrowserAccountsContext,
  Locale
} from "../../types";
import {
  api,
  ApiError,
  getApiErrorMessage,
  type ApiRequestInit
} from "../../lib/api";

type BrowserAccountAction = `select:${string}` | "add";
const BROWSER_ACCOUNT_CSRF_PATH = "/api/browser-accounts/csrf";

/**
 * Called when an account is picked in the bottom account strip.  The second
 * argument deliberately keeps the privileged selection request in this
 * component: the parent can put the final "continue" button anywhere in its
 * layout without duplicating the browser-context CSRF flow.
 */
export type BrowserAccountSelectedHandler = (
  account: BrowserAccount,
  continueWithAccount: () => Promise<void>
) => void;

export type BrowserAccountsLoadedHandler = (
  accounts: BrowserAccount[],
  context: BrowserAccountsContext,
  continueWithAccount: (accountRef: string) => Promise<void>
) => void;

export type AccountChooserProps = {
  returnTo: string;
  /** Retained for source compatibility with the previous chooser API. */
  locale?: Locale;
  t: (key: TranslationKey) => string;
  /**
   * A controlled selection.  Omit this prop to let the strip highlight its
   * most recently signed-in account by default.
   */
  selectedAccountRef?: string | null;
  /**
   * OIDC account choice must consume the authorization interaction; ordinary
   * login pages only activate the selected remembered browser session.
   */
  selectionMode?: "select" | "activate";
  /**
   * When provided, selecting an item only notifies the parent.  Without it,
   * the legacy immediate-select-and-redirect behaviour is kept.
   */
  onAccountSelected?: BrowserAccountSelectedHandler;
  /** Receives accounts in most-recent-login order after every successful load. */
  onAccountsLoaded?: BrowserAccountsLoadedHandler;
  /**
   * Receives a server-generated, account-flow-bound login URL.  Consumers can
   * render sign-in/registration inline rather than navigating to a new page.
   */
  onLoginAnother?: (loginUrl: string) => void | Promise<void>;
};

function browserAccountRequest<T>(path: string, options: Omit<ApiRequestInit, "csrfTokenPath"> = {}): Promise<T> {
  return api<T>(path, {
    ...options,
    csrfTokenPath: BROWSER_ACCOUNT_CSRF_PATH
  });
}

/**
 * Starts a server-bound login flow for an additional browser account. Both
 * the account strip and the admin-console switch action use this helper so
 * the existing browser context (and its remembered accounts) is retained.
 */
export async function startBrowserAccountLogin(returnTo: string): Promise<string> {
  const result = await browserAccountRequest<BrowserAccountAddResponse>(
    "/api/browser-accounts/add/start",
    { method: "POST", body: JSON.stringify({ return_to: returnTo }) }
  );
  if (!result?.login_url) throw new ApiError("", 500, "invalid_response", result);
  return result.login_url;
}

async function fetchBrowserAccounts(
  returnTo: string,
  signal?: AbortSignal
): Promise<BrowserAccountsContext> {
  const query = new URLSearchParams({ return_to: returnTo });
  const result = await api<BrowserAccountsContext>(`/api/browser-accounts?${query}`, { signal });
  if (!isBrowserAccountsContext(result)) {
    throw new ApiError("", 500, "invalid_response", result);
  }
  return result;
}

function isBrowserAccountsContext(value: unknown): value is BrowserAccountsContext {
  return typeof value === "object"
    && value !== null
    && Array.isArray((value as { accounts?: unknown }).accounts);
}

function accountHandle(account: BrowserAccount): string {
  return account.user.username.trim() || account.user.email.trim();
}

function sortAccounts(accounts: BrowserAccount[]): BrowserAccount[] {
  return [...accounts].sort((left, right) => {
    const recent = right.last_login_at - left.last_login_at;
    if (recent !== 0) return recent;
    const current = Number(right.current) - Number(left.current);
    if (current !== 0) return current;
    return left.account_ref.localeCompare(right.account_ref);
  });
}

function actionErrorMessage(error: unknown, fallback: string): string {
  return getApiErrorMessage(error, fallback);
}

/**
 * A compact account strip intended for the bottom of the unified auth page.
 * It still owns the CSRF-protected browser-account APIs, while a parent can
 * opt into controlled selection and render the selected account's details
 * above the strip.
 */
export function AccountChooser({
  returnTo,
  t,
  selectedAccountRef,
  selectionMode = "select",
  onAccountSelected,
  onAccountsLoaded,
  onLoginAnother
}: AccountChooserProps) {
  const tRef = useRef(t);
  const onAccountsLoadedRef = useRef(onAccountsLoaded);
  const selectionModeRef = useRef(selectionMode);
  tRef.current = t;
  onAccountsLoadedRef.current = onAccountsLoaded;
  selectionModeRef.current = selectionMode;

  const [context, setContext] = useState<BrowserAccountsContext | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [action, setAction] = useState<BrowserAccountAction | null>(null);
  const [localSelectedAccountRef, setLocalSelectedAccountRef] = useState<string | null>(null);

  const selectAccount = useCallback(async (accountRef: string) => {
    setAction(`select:${accountRef}`);
    setError("");
    try {
      const result = await browserAccountRequest<BrowserAccountSelectionResponse>(
        selectionModeRef.current === "activate"
          ? "/api/browser-accounts/activate"
          : "/api/browser-accounts/select",
        {
          method: "POST",
          body: JSON.stringify({ account_ref: accountRef, return_to: returnTo })
        }
      );
      if (!result?.continue_to) {
        throw new ApiError("", 500, "invalid_response", result);
      }
      window.location.assign(result.continue_to);
    } catch (nextError) {
      setError(actionErrorMessage(nextError, tRef.current("browserAccountSelectFailed")));
    } finally {
      setAction(null);
    }
  }, [returnTo]);

  const loadAccounts = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    setError("");
    try {
      const loaded = await fetchBrowserAccounts(returnTo, signal);
      const nextContext = { ...loaded, accounts: sortAccounts(loaded.accounts) };
      setContext(nextContext);
      onAccountsLoadedRef.current?.(
        nextContext.accounts,
        nextContext,
        selectAccount
      );
    } catch (nextError) {
      if (nextError instanceof DOMException && nextError.name === "AbortError") return;
      setError(actionErrorMessage(nextError, tRef.current("browserAccountsLoadFailed")));
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [returnTo, selectAccount]);

  useEffect(() => {
    const controller = new AbortController();
    void loadAccounts(controller.signal);
    return () => controller.abort();
  }, [loadAccounts]);

  const accounts = useMemo(() => context?.accounts ?? [], [context]);
  const selectedRef = selectedAccountRef !== undefined
    ? selectedAccountRef
    : (accounts.some((account) => account.account_ref === localSelectedAccountRef)
      ? localSelectedAccountRef
      : accounts[0]?.account_ref ?? null);

  function chooseAccount(account: BrowserAccount) {
    setLocalSelectedAccountRef(account.account_ref);
    if (onAccountSelected) {
      onAccountSelected(account, () => selectAccount(account.account_ref));
      return;
    }
    void selectAccount(account.account_ref);
  }

  async function addAccount() {
    setAction("add");
    setError("");
    try {
      const loginUrl = await startBrowserAccountLogin(returnTo);
      if (onLoginAnother) {
        await onLoginAnother(loginUrl);
      } else {
        window.location.assign(loginUrl);
      }
    } catch (nextError) {
      setError(actionErrorMessage(nextError, t("browserAccountAddFailed")));
    } finally {
      setAction(null);
    }
  }

  const busy = action !== null;

  return (
    <section className="account-switcher-bar" aria-label={t("selectAccount")} aria-busy={loading || busy}>
      {error && <div className="account-switcher-error error" role="alert">{error}</div>}
      {loading && !context ? (
        <div className="account-switcher-loading" role="status" aria-live="polite">
          <RefreshCw className="spin" size={16} aria-hidden="true" />
          <span>{t("loading")}</span>
        </div>
      ) : context ? (
        <div className="account-switcher-row">
          <ul className="account-switcher-list" aria-label={t("selectAccount")}>
            {accounts.length > 0 ? accounts.map((account) => {
              const selected = account.account_ref === selectedRef;
              const selecting = action === `select:${account.account_ref}`;
              const handle = accountHandle(account);
              return (
                <li className="account-switcher-list-item" key={account.account_ref}>
                  <button
                    type="button"
                    className={`account-switcher-item${selected ? " selected" : ""}${account.current ? " current" : ""}`}
                    aria-current={selected ? "true" : undefined}
                    aria-label={`${t("useAccount")}: ${account.user.email}`}
                    aria-busy={selecting || undefined}
                    disabled={busy}
                    title={account.user.email}
                    onClick={() => chooseAccount(account)}
                  >
                    <span className="account-switcher-avatar" aria-hidden="true">{handle.slice(0, 1).toLocaleUpperCase()}</span>
                    <span className="account-switcher-name">{handle}</span>
                    {selecting && <RefreshCw className="spin" size={14} aria-hidden="true" />}
                  </button>
                </li>
              );
            }) : (
              <li className="account-switcher-empty" role="status">{t("noBrowserAccounts")}</li>
            )}
          </ul>
          <button
            className="account-switcher-add"
            type="button"
            disabled={busy}
            aria-label={t("useAnotherAccount")}
            title={t("useAnotherAccount")}
            onClick={() => void addAccount()}
          >
            {action === "add" ? <RefreshCw className="spin" size={18} aria-hidden="true" /> : <Plus size={20} aria-hidden="true" />}
          </button>
        </div>
      ) : (
        <button className="secondary-button account-switcher-retry" type="button" onClick={() => void loadAccounts()}>
          <RefreshCw size={16} />{t("retry")}
        </button>
      )}
      {busy && <span className="sr-only" role="status" aria-live="polite">{t("loading")}</span>}
    </section>
  );
}
