import { Coins, ExternalLink, RefreshCw } from "lucide-react";
import { FormEvent, forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState } from "react";
import { Card, EmptyState, Field, SelectField, StatusBadge } from "../../components/ui";
import { ApiError } from "../../lib/api";
import * as billingApi from "../../lib/api/billing";
import type { BillingWorkspaceQuery } from "../../lib/api/billing";
import type { BillingCheckout, BillingRecharge, BillingWallet, Locale } from "../../types";
import type { TranslationKey } from "../../i18n";

type Copy = (key: TranslationKey) => string;

function billingError(reason: unknown, fallback: TranslationKey, t: Copy): string {
  if (reason instanceof ApiError) {
    if (reason.code === "network_error") return t("networkError");
    if (reason.code === "csrf_failed") return t("sessionExpired");
    if (reason.status >= 500 || reason.status === 401 || reason.status === 403) return t(fallback);
  }
  const message = reason instanceof Error ? reason.message : "";
  if (message === "billing idempotency_key is already used for another recharge") {
    return t("billingRechargeRetryDifferent");
  }
  if (message.startsWith("billing ")) return t(fallback);
  return message || t(fallback);
}

function money(value: number, currency: string, minorUnit = 2): string {
  const unit = Math.max(0, Math.min(8, minorUnit));
  return `${(value / 10 ** unit).toFixed(unit)} ${currency}`;
}

function statusTone(status: string): "success" | "warning" | "danger" | "neutral" | "info" {
  if (status === "paid" || status === "completed") return "success";
  if (status === "creating" || status === "pending" || status === "processing" || status === "reconcile") return "warning";
  if (status === "closed" || status === "failed" || status === "reversed") return "danger";
  return "neutral";
}

const ACTIVE_ORDER_STATUSES = new Set(["creating", "pending", "processing", "reconcile"]);
const TERMINAL_ORDER_STATUSES = new Set(["paid", "completed", "failed", "closed", "reversed"]);

function isActiveOrderStatus(status: string): boolean {
  return ACTIVE_ORDER_STATUSES.has(status);
}

function isTerminalOrderStatus(status: string): boolean {
  return TERMINAL_ORDER_STATUSES.has(status);
}

function isAbortError(reason: unknown): boolean {
  return reason instanceof Error && reason.name === "AbortError";
}

function createAbortError(): Error {
  if (typeof DOMException !== "undefined") {
    return new DOMException("The operation was aborted.", "AbortError");
  }
  const error = new Error("The operation was aborted.");
  error.name = "AbortError";
  return error;
}

function waitFor(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(createAbortError());
      return;
    }
    const timer = window.setTimeout(resolve, milliseconds);
    const abort = () => {
      window.clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(createAbortError());
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}

function accountLabel(wallet: BillingWallet, t: Copy): string {
  if (wallet.account_kind === "user_global") return t("billingGlobalWallet");
  if (wallet.account_kind === "user_application") return `${t("billingApplicationWallet")} · ${wallet.application_id ?? "-"}`;
  return wallet.account_kind;
}

export type WalletWorkspaceHandle = {
  reload: () => Promise<boolean>;
};

type WalletWorkspaceProps = { locale: Locale; t: Copy; orderReference?: string | null };

const EMPTY_BILLING_WORKSPACE: BillingWorkspaceQuery = {
  wallets: [],
  providers: [],
  transactions: [],
  recharges: []
};

export const WalletWorkspace = forwardRef<WalletWorkspaceHandle, WalletWorkspaceProps>(function WalletWorkspace(
  { locale, t, orderReference },
  ref
) {
  const [workspace, setWorkspace] = useState<BillingWorkspaceQuery>(EMPTY_BILLING_WORKSPACE);
  const [amount, setAmount] = useState("10.00");
  const [currency, setCurrency] = useState("CNY");
  const [provider, setProvider] = useState("");
  const [checkout, setCheckout] = useState<BillingCheckout | null>(null);
  const [returnedOrder, setReturnedOrder] = useState<BillingRecharge | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const rechargeIdempotencyKey = useRef<string | null>(null);
  const rechargeRequestSignature = useRef<string | null>(null);
  const loadSequence = useRef(0);
  const loadAbortController = useRef<AbortController | null>(null);
  const loadRef = useRef<(force?: boolean) => Promise<boolean>>(() => Promise.resolve(false));
  const orderPollSequence = useRef(0);
  const orderPollAbortController = useRef<AbortController | null>(null);

  const { wallets, providers, transactions, recharges } = workspace;
  const walletView = useMemo(() => billingApi.createBillingWalletViewModel(wallets), [wallets]);
  const { currencies } = walletView;

  async function load(force = false): Promise<boolean> {
    const sequence = ++loadSequence.current;
    loadAbortController.current?.abort();
    const controller = new AbortController();
    loadAbortController.current = controller;
    setLoading(true);
    setError("");
    try {
      const nextWorkspace = await billingApi.listBillingWorkspace({ signal: controller.signal, force });
      if (sequence !== loadSequence.current || controller.signal.aborted) return false;
      setWorkspace(nextWorkspace);
      const matchedOrder = orderReference
        ? nextWorkspace.recharges.find((order) => order.merchant_order_no === orderReference || order.id === orderReference) ?? null
        : null;
      setReturnedOrder(matchedOrder);
      setCurrency((current) => current || nextWorkspace.wallets[0]?.currency || "CNY");
      setProvider((current) => current || nextWorkspace.providers[0]?.slug || "");
      return true;
    } catch (reason) {
      if (sequence !== loadSequence.current || controller.signal.aborted || (reason instanceof Error && reason.name === "AbortError")) return false;
      setError(billingError(reason, "billingLoadFailed", t));
      return false;
    } finally {
      if (sequence === loadSequence.current) {
        setLoading(false);
        if (loadAbortController.current === controller) loadAbortController.current = null;
      }
    }
  }

  // The poller must call the latest loader without making its effect depend
  // on the loader's render-time function identity.
  loadRef.current = load;

  useImperativeHandle(ref, () => ({ reload: () => load(true) }), [load]);

  useEffect(() => {
    void load();
    return () => {
      loadSequence.current += 1;
      loadAbortController.current?.abort();
      loadAbortController.current = null;
      orderPollSequence.current += 1;
      orderPollAbortController.current?.abort();
      orderPollAbortController.current = null;
    };
  }, [orderReference]);

  async function submitRecharge(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const major = Number(amount);
      const amountMinor = Math.round(major * 10 ** walletView.minorUnitFor(currency));
      if (!Number.isFinite(major) || amountMinor <= 0 || !provider) throw new Error(t("billingRechargeInvalid"));
      const requestSignature = `${amountMinor}:${currency}:${provider}`;
      if (rechargeRequestSignature.current !== requestSignature) {
        rechargeIdempotencyKey.current = null;
        rechargeRequestSignature.current = requestSignature;
      }
      const idempotencyKey = rechargeIdempotencyKey.current ?? `ui-${crypto.randomUUID()}`;
      rechargeIdempotencyKey.current = idempotencyKey;
      const result = await billingApi.createBillingRecharge({
        amount_minor: amountMinor,
        currency,
        provider_slug: provider,
        idempotency_key: idempotencyKey
      });
      setCheckout(result);
      setMessage(t("billingRechargeCreated"));
      if (result.checkout_kind === "redirect") window.location.assign(result.checkout_value);
      const refreshed = await load(true);
      if (refreshed) {
        rechargeIdempotencyKey.current = null;
        rechargeRequestSignature.current = null;
      }
    } catch (reason) {
      setError(billingError(reason, "billingRechargeFailed", t));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!orderReference || !returnedOrder
      || (returnedOrder.merchant_order_no !== orderReference && returnedOrder.id !== orderReference)
      || !isActiveOrderStatus(returnedOrder.status)) return;
    const sequence = ++orderPollSequence.current;
    orderPollAbortController.current?.abort();
    const controller = new AbortController();
    orderPollAbortController.current = controller;
    const orderId = returnedOrder.id;
    const startedAt = Date.now();

    const poll = async () => {
      let delay = 2_000;
      while (Date.now() - startedAt < 5 * 60_000) {
        await waitFor(delay, controller.signal);
        if (sequence !== orderPollSequence.current || controller.signal.aborted) return;
        let nextOrder: BillingRecharge;
        try {
          // Reconcile only the returned order. Full wallet/history reads are
          // reserved for the initial load and the first terminal transition.
          nextOrder = await billingApi.queryBillingRecharge(orderId, { signal: controller.signal });
        } catch (reason) {
          if (sequence !== orderPollSequence.current || controller.signal.aborted || isAbortError(reason)) return;
          if (reason instanceof ApiError && [401, 403, 404].includes(reason.status)) {
            setError(billingError(reason, "billingLoadFailed", t));
            return;
          }
          delay = Math.min(delay * 2, 30_000);
          continue;
        }
        if (sequence !== orderPollSequence.current || controller.signal.aborted) return;
        setReturnedOrder(nextOrder);
        if (isTerminalOrderStatus(nextOrder.status)) {
          await loadRef.current(true);
          return;
        }
        delay = Math.min(delay * 2, 30_000);
      }
    };
    void poll().catch((reason) => {
      if (sequence === orderPollSequence.current && !controller.signal.aborted && !isAbortError(reason)) {
        setError(billingError(reason, "billingLoadFailed", t));
      }
    });
    return () => {
      if (orderPollAbortController.current === controller) orderPollAbortController.current = null;
      controller.abort();
    };
  }, [orderReference, returnedOrder?.id]);

  return (
    <section className="management-list billing-workspace">
      <div className="section-heading">
        <div><span className="eyebrow"><Coins size={14} />{t("billing")}</span><h2>{t("billingWallet")}</h2><p>{t("billingWalletHint")}</p></div>
        <button type="button" className="secondary-button" onClick={() => void load(true)} disabled={loading || busy}><RefreshCw size={14} />{t("refresh")}</button>
      </div>
      {error && <div className="error" role="alert">{error}</div>}
      {message && <div className="success" role="status">{message}</div>}
      {returnedOrder && (
        <div className="billing-returned-order" role="status" aria-live="polite">
          <div><strong>{t("billingReturnedOrder")}</strong><span>{returnedOrder.merchant_order_no}</span></div>
          <StatusBadge tone={statusTone(returnedOrder.status)}>{returnedOrder.status}</StatusBadge>
          <p>{isActiveOrderStatus(returnedOrder.status) ? t("billingOrderPending") : returnedOrder.status === "paid" ? t("billingOrderPaid") : t("billingOrderClosed")}</p>
        </div>
      )}
      {loading ? <div className="loading-state">{t("loading")}</div> : <>
        <div className="billing-wallet-grid">
          {wallets.length === 0 ? <EmptyState title={t("billingNoWallets")} description={t("billingNoWalletsHint")} icon={<Coins size={22} />} /> : wallets.map((wallet) => <Card key={wallet.id} className="billing-wallet-card"><span className="muted">{accountLabel(wallet, t)}</span><strong>{money(wallet.available_minor, wallet.currency, wallet.minor_unit)}</strong><small>{t("billingReserved")}: {money(wallet.reserved_minor, wallet.currency, wallet.minor_unit)}</small></Card>)}
        </div>
        <div className="billing-actions-grid">
          <Card as="section">
            <h3>{t("billingRecharge")}</h3>
            <p className="muted">{t("billingRechargeHint")}</p>
            <form onSubmit={submitRecharge}>
              <Field label={t("billingAmount")} type="number" min="0.01" step="0.01" value={amount} onChange={setAmount} required />
              <SelectField label={t("billingCurrency")} value={currency} onChange={setCurrency}>{(currencies.length ? currencies : ["CNY"]).map((item) => <option value={item} key={item}>{item}</option>)}</SelectField>
              <SelectField label={t("billingProvider")} value={provider} onChange={setProvider}>{providers.map((item) => <option value={item.slug} key={item.slug}>{item.slug}</option>)}</SelectField>
              <button type="submit" className="primary-action" disabled={busy || providers.length === 0}><Coins size={14} />{t("billingStartRecharge")}</button>
            </form>
            {checkout?.checkout_kind === "qr" && <div className="billing-checkout" role="status"><strong>{t("billingScanQr")}</strong><code>{checkout.checkout_value}</code></div>}
            {checkout?.checkout_kind === "redirect" && <a href={checkout.checkout_value} className="text-button"><ExternalLink size={14} />{t("billingOpenPayment")}</a>}
          </Card>
        </div>
        <Card as="section"><h3>{t("billingRechargeHistory")}</h3>{recharges.length === 0 ? <EmptyState title={t("billingNoRecharges")} /> : <div className="table-scroll"><table><thead><tr><th>{t("billingOrder")}</th><th>{t("billingAmount")}</th><th>{t("status")}</th><th>{t("registeredAt")}</th></tr></thead><tbody>{recharges.map((order) => <tr key={order.id}><td>{order.merchant_order_no}</td><td>{money(order.amount.amount_minor, order.amount.currency, order.amount.minor_unit ?? walletView.minorUnitFor(order.amount.currency))}</td><td><StatusBadge tone={statusTone(order.status)}>{order.status}</StatusBadge></td><td>{new Date(order.created_at * 1000).toLocaleString(locale)}</td></tr>)}</tbody></table></div>}</Card>
        <Card as="section"><h3>{t("billingTransactionHistory")}</h3>{transactions.length === 0 ? <EmptyState title={t("billingNoTransactions")} /> : <div className="table-scroll"><table><thead><tr><th>{t("billingTransactionKind")}</th><th>{t("billingAmount")}</th><th>{t("status")}</th><th>{t("registeredAt")}</th></tr></thead><tbody>{transactions.map((item) => <tr key={item.id}><td>{item.kind}</td><td>{money(item.amount_minor, item.currency, item.minor_unit ?? walletView.minorUnitFor(item.currency))}</td><td><StatusBadge tone={statusTone(item.status)}>{item.status}</StatusBadge></td><td>{new Date(item.created_at * 1000).toLocaleString(locale)}</td></tr>)}</tbody></table></div>}</Card>
      </>}
    </section>
  );
});
