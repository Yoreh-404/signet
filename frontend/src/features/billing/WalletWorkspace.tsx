import { ArrowLeftRight, Coins, ExternalLink, RefreshCw } from "lucide-react";
import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import { Card, EmptyState, Field, SelectField, StatusBadge } from "../../components/ui";
import { api, ApiError } from "../../lib/api";
import type { BillingCheckout, BillingProvider, BillingRecharge, BillingTransaction, BillingWallet, Locale } from "../../types";
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
  if (status === "pending" || status === "processing") return "warning";
  if (status === "closed" || status === "failed" || status === "reversed") return "danger";
  return "neutral";
}

function accountLabel(wallet: BillingWallet, t: Copy): string {
  if (wallet.account_kind === "user_global") return t("billingGlobalWallet");
  if (wallet.account_kind === "user_application") return `${t("billingApplicationWallet")} · ${wallet.application_id ?? "-"}`;
  return wallet.account_kind;
}

export function WalletWorkspace({ locale, t, orderReference }: { locale: Locale; t: Copy; orderReference?: string | null }) {
  const [wallets, setWallets] = useState<BillingWallet[]>([]);
  const [providers, setProviders] = useState<BillingProvider[]>([]);
  const [transactions, setTransactions] = useState<BillingTransaction[]>([]);
  const [recharges, setRecharges] = useState<BillingRecharge[]>([]);
  const [amount, setAmount] = useState("10.00");
  const [currency, setCurrency] = useState("CNY");
  const [provider, setProvider] = useState("");
  const [applicationId, setApplicationId] = useState("");
  const [transferAmount, setTransferAmount] = useState("");
  const [transferDirection, setTransferDirection] = useState("to_application");
  const [checkout, setCheckout] = useState<BillingCheckout | null>(null);
  const [returnedOrder, setReturnedOrder] = useState<BillingRecharge | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const rechargeIdempotencyKey = useRef<string | null>(null);
  const rechargeRequestSignature = useRef<string | null>(null);
  const transferIdempotencyKey = useRef<string | null>(null);

  const currencies = useMemo(
    () => Array.from(new Set(wallets.map((wallet) => wallet.currency))).sort(),
    [wallets]
  );

  const currencyMinorUnits = useMemo(
    () => new Map(wallets.map((wallet) => [wallet.currency, wallet.minor_unit ?? 2])),
    [wallets]
  );

  function minorUnitFor(currencyCode: string): number {
    return currencyMinorUnits.get(currencyCode) ?? 2;
  }

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [nextWallets, nextProviders, nextTransactions, nextRecharges] = await Promise.all([
        api<BillingWallet[]>("/api/me/billing/wallets"),
        api<BillingProvider[]>("/api/me/billing/providers"),
        api<BillingTransaction[]>("/api/me/billing/transactions"),
        api<BillingRecharge[]>("/api/me/billing/recharges")
      ]);
      setWallets(nextWallets);
      setProviders(nextProviders);
      setTransactions(nextTransactions);
      setRecharges(nextRecharges);
      const matchedOrder = orderReference
        ? nextRecharges.find((order) => order.merchant_order_no === orderReference || order.id === orderReference) ?? null
        : null;
      setReturnedOrder(matchedOrder);
      setCurrency((current) => current || nextWallets[0]?.currency || "CNY");
      setProvider((current) => current || nextProviders[0]?.slug || "");
    } catch (reason) {
      setError(billingError(reason, "billingLoadFailed", t));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    void load();
  }, [orderReference]);

  async function submitRecharge(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const major = Number(amount);
      const amountMinor = Math.round(major * 10 ** minorUnitFor(currency));
      if (!Number.isFinite(major) || amountMinor <= 0 || !provider) throw new Error(t("billingRechargeInvalid"));
      const requestSignature = `${amountMinor}:${currency}:${provider}`;
      if (rechargeRequestSignature.current !== requestSignature) {
        rechargeIdempotencyKey.current = null;
        rechargeRequestSignature.current = requestSignature;
      }
      const idempotencyKey = rechargeIdempotencyKey.current ?? `ui-${crypto.randomUUID()}`;
      rechargeIdempotencyKey.current = idempotencyKey;
      const result = await api<BillingCheckout>("/api/me/billing/recharges", {
        method: "POST",
        body: JSON.stringify({
          amount_minor: amountMinor,
          currency,
          provider_slug: provider,
          idempotency_key: idempotencyKey
        })
      });
      rechargeIdempotencyKey.current = null;
      rechargeRequestSignature.current = null;
      setCheckout(result);
      setMessage(t("billingRechargeCreated"));
      if (result.checkout_kind === "redirect") window.location.assign(result.checkout_value);
      await load();
    } catch (reason) {
      setError(billingError(reason, "billingRechargeFailed", t));
    } finally {
      setBusy(false);
    }
  }

  async function submitTransfer(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const major = Number(transferAmount);
      const amountMinor = Math.round(major * 10 ** minorUnitFor(currency));
      if (!applicationId.trim() || !Number.isFinite(major) || amountMinor <= 0) throw new Error(t("billingTransferInvalid"));
      const source = transferDirection === "to_application" ? t("billingTransferToApplication").split(" → ")[0] : t("billingTransferFromApplication").split(" → ")[0];
      const destination = transferDirection === "to_application" ? t("billingTransferToApplication").split(" → ")[1] : t("billingTransferFromApplication").split(" → ")[1];
      const confirmation = t("billingTransferConfirm")
        .replace("{amount}", money(amountMinor, currency, minorUnitFor(currency)))
        .replace("{source}", source)
        .replace("{destination}", `${destination} (${applicationId.trim()})`);
      if (!window.confirm(confirmation)) return;
      const idempotencyKey = transferIdempotencyKey.current ?? `ui-${crypto.randomUUID()}`;
      transferIdempotencyKey.current = idempotencyKey;
      await api("/api/me/billing/transfers", {
        method: "POST",
        body: JSON.stringify({
          application_id: applicationId.trim(),
          currency,
          amount_minor: amountMinor,
          direction: transferDirection,
          idempotency_key: idempotencyKey
        })
      });
      setMessage(t("billingTransferCreated"));
      setTransferAmount("");
      transferIdempotencyKey.current = null;
      await load();
    } catch (reason) {
      setError(billingError(reason, "billingTransferFailed", t));
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    if (!orderReference || !returnedOrder || returnedOrder.status !== "pending") return;
    const timer = window.setTimeout(() => void load(), 5000);
    return () => window.clearTimeout(timer);
  }, [orderReference, returnedOrder?.status]);

  return (
    <section className="management-list billing-workspace">
      <div className="section-heading">
        <div><span className="eyebrow"><Coins size={14} />{t("billing")}</span><h2>{t("billingWallet")}</h2><p>{t("billingWalletHint")}</p></div>
        <button type="button" className="secondary-button" onClick={() => void load()} disabled={loading || busy}><RefreshCw size={14} />{t("refresh")}</button>
      </div>
      {error && <div className="error" role="alert">{error}</div>}
      {message && <div className="success" role="status">{message}</div>}
      {returnedOrder && (
        <div className="billing-returned-order" role="status" aria-live="polite">
          <div><strong>{t("billingReturnedOrder")}</strong><span>{returnedOrder.merchant_order_no}</span></div>
          <StatusBadge tone={statusTone(returnedOrder.status)}>{returnedOrder.status}</StatusBadge>
          <p>{returnedOrder.status === "pending" ? t("billingOrderPending") : returnedOrder.status === "paid" ? t("billingOrderPaid") : t("billingOrderClosed")}</p>
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
          <Card as="section">
            <h3>{t("billingTransfer")}</h3>
            <p className="muted">{t("billingTransferHint")}</p>
            <form onSubmit={submitTransfer}>
              <Field label={t("billingApplicationId")} value={applicationId} onChange={setApplicationId} required />
              <Field label={t("billingAmount")} type="number" min="0.01" step="0.01" value={transferAmount} onChange={setTransferAmount} required />
              <SelectField label={t("billingTransferDirection")} value={transferDirection} onChange={setTransferDirection}><option value="to_application">{t("billingTransferToApplication")}</option><option value="from_application">{t("billingTransferFromApplication")}</option></SelectField>
              <button type="submit" className="secondary-button" disabled={busy}><ArrowLeftRight size={14} />{t("billingTransferAction")}</button>
            </form>
          </Card>
        </div>
        <Card as="section"><h3>{t("billingRechargeHistory")}</h3>{recharges.length === 0 ? <EmptyState title={t("billingNoRecharges")} /> : <div className="table-scroll"><table><thead><tr><th>{t("billingOrder")}</th><th>{t("billingAmount")}</th><th>{t("status")}</th><th>{t("registeredAt")}</th></tr></thead><tbody>{recharges.map((order) => <tr key={order.id}><td>{order.merchant_order_no}</td><td>{money(order.amount.amount_minor, order.amount.currency, order.amount.minor_unit ?? minorUnitFor(order.amount.currency))}</td><td><StatusBadge tone={statusTone(order.status)}>{order.status}</StatusBadge></td><td>{new Date(order.created_at * 1000).toLocaleString(locale)}</td></tr>)}</tbody></table></div>}</Card>
        <Card as="section"><h3>{t("billingTransactionHistory")}</h3>{transactions.length === 0 ? <EmptyState title={t("billingNoTransactions")} /> : <div className="table-scroll"><table><thead><tr><th>{t("billingTransactionKind")}</th><th>{t("billingAmount")}</th><th>{t("status")}</th><th>{t("registeredAt")}</th></tr></thead><tbody>{transactions.map((item) => <tr key={item.id}><td>{item.kind}</td><td>{money(item.amount_minor, item.currency, item.minor_unit ?? minorUnitFor(item.currency))}</td><td><StatusBadge tone={statusTone(item.status)}>{item.status}</StatusBadge></td><td>{new Date(item.created_at * 1000).toLocaleString(locale)}</td></tr>)}</tbody></table></div>}</Card>
      </>}
    </section>
  );
}
