import { ArrowRight, Coins } from "lucide-react";
import type { FormEvent } from "react";
import { useEffect, useMemo, useRef, useState } from "react";
import * as applicationApi from "../../lib/api/applications";
import * as billingApi from "../../lib/api/billing";
import type { ApplicationBillingSettings, BillingWallet } from "../../types";
import type { ApplicationRequestGuard } from "./application-request-guard";
import { Input, ModuleHeader, ModuleSave, Toggle } from "./components/ApplicationModulePrimitives";
import { stableDomainEqual } from "../admin/stable-domain-comparator";

type BillingCopy = {
  billing: string;
  billingHint: string;
  acceptSignetBalance: string;
  acceptSignetBalanceHint: string;
  walletMode: string;
  sharedWallet: string;
  isolatedWallet: string;
  walletModeLocked: string;
  billingCurrency: string;
  billingCurrencies: string;
  billingCurrenciesHint: string;
  walletOverview: string;
  walletAvailable: string;
  walletReserved: string;
  walletTransferHint: string;
  transferAmount: string;
  transferDirection: string;
  transferToApplication: string;
  transferFromApplication: string;
  executeTransfer: string;
  noApplicationWallet: string;
  save: string;
  saving: string;
  saveFailed: string;
  loadFailed: string;
  retry: string;
  saved: string;
};

export function BillingModule({
  applicationId,
  canManage,
  copy,
  requestGuard,
  onDirtyChange,
  onEnabledChange
}: {
  applicationId: string;
  canManage: boolean;
  copy: BillingCopy;
  requestGuard: ApplicationRequestGuard;
  onDirtyChange: (dirty: boolean) => void;
  onEnabledChange: (enabled: boolean) => void;
}) {
  const [settings, setSettings] = useState<ApplicationBillingSettings | null>(null);
  const [baseline, setBaseline] = useState<ApplicationBillingSettings | null>(null);
  const [wallets, setWallets] = useState<BillingWallet[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const [reloadToken, setReloadToken] = useState(0);
  const [saving, setSaving] = useState(false);
  const [transferAmount, setTransferAmount] = useState("");
  const [transferCurrency, setTransferCurrency] = useState("");
  const [transferDirection, setTransferDirection] = useState<"to_application" | "from_application">("to_application");
  const [transferSaving, setTransferSaving] = useState(false);
  const transferIdempotencyKey = useRef<string | null>(null);
  const transferRequestSignature = useRef<string | null>(null);
  const walletView = useMemo(() => billingApi.createBillingWalletViewModel(wallets), [wallets]);

  useEffect(() => {
    setSettings(null);
    setBaseline(null);
    setWallets([]);
    setError("");
    setFeedback("");
    setTransferAmount("");
    setTransferCurrency("");
    setTransferDirection("to_application");
    setSaving(false);
    setTransferSaving(false);
    transferIdempotencyKey.current = null;
    transferRequestSignature.current = null;
    onEnabledChange(false);
    onDirtyChange(false);
  }, [applicationId, onDirtyChange, onEnabledChange]);

  useEffect(() => {
    const request = requestGuard.begin(applicationId, { scope: "billing:load", kind: "read" });
    if (!request) return;
    setLoading(true);
    setError("");
    void Promise.all([
      applicationApi.getApplicationBillingSettings(applicationId, { signal: request.signal }),
      billingApi.listBillingWallets({ signal: request.signal }).catch(() => [] as BillingWallet[])
    ])
      .then(([nextSettings, nextWallets]) => {
        if (!requestGuard.isCurrent(request)) return;
        setSettings(nextSettings);
        setBaseline(nextSettings);
        setWallets(nextWallets);
        setTransferCurrency((current) => current || nextWallets.find((wallet) => wallet.currency)?.currency || "CNY");
        onEnabledChange(nextSettings.accept_signet_balance);
      })
      .catch(() => {
        if (!requestGuard.isCurrent(request)) return;
        setSettings(null);
        setBaseline(null);
        setWallets([]);
        setError(copy.loadFailed);
        onEnabledChange(false);
      })
      .finally(() => {
        if (requestGuard.isCurrent(request)) setLoading(false);
        requestGuard.finish(request, false);
      });
    return () => requestGuard.finish(request, false);
  }, [applicationId, copy.loadFailed, onEnabledChange, reloadToken, requestGuard]);

  useEffect(() => {
    const dirty = Boolean(
      settings
      && baseline
      && !stableDomainEqual(settings, baseline)
    ) || transferAmount.trim().length > 0;
    onDirtyChange(dirty);
  }, [baseline, onDirtyChange, settings, transferAmount]);

  useEffect(() => () => onDirtyChange(false), [onDirtyChange]);

  async function saveSettings() {
    if (!settings || !canManage) return;
    const request = requestGuard.begin(applicationId, {
      scope: "billing:settings",
      kind: "mutation",
      payloadFingerprint: JSON.stringify(settings)
    });
    if (!request) return;
    setSaving(true);
    let committed = false;
    try {
      const nextSettings = await applicationApi.updateApplicationBillingSettings(applicationId, {
        accept_signet_balance: settings.accept_signet_balance,
        wallet_mode: settings.wallet_mode,
        supported_currencies: settings.supported_currencies
      }, { signal: request.signal, idempotencyKey: request.idempotencyKey ?? undefined });
      if (!requestGuard.isCurrent(request)) return;
      setSettings(nextSettings);
      setBaseline(nextSettings);
      onEnabledChange(nextSettings.accept_signet_balance);
      setFeedback(copy.saved);
      committed = true;
    } catch {
      if (requestGuard.isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (requestGuard.isCurrent(request)) setSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  async function transfer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!settings || settings.wallet_mode !== "isolated") return;
    const amount = Number(transferAmount);
    const currency = transferCurrency || settings.supported_currencies[0] || walletView.currencies[0] || "CNY";
    const wallet = walletView.find("user_application", applicationId, currency)
      ?? walletView.find("user_global", undefined, currency);
    const minorUnit = wallet?.minor_unit ?? 2;
    const amountMinor = Math.round(amount * 10 ** minorUnit);
    if (!Number.isFinite(amount) || amountMinor <= 0) {
      setFeedback(copy.saveFailed);
      return;
    }
    const requestSignature = `${applicationId}:${amountMinor}:${currency}:${transferDirection}`;
    const request = requestGuard.begin(applicationId, {
      scope: "billing:transfer",
      kind: "mutation",
      payloadFingerprint: requestSignature
    });
    if (!request) return;
    if (transferRequestSignature.current !== requestSignature) {
      transferIdempotencyKey.current = null;
      transferRequestSignature.current = requestSignature;
    }
    setTransferSaving(true);
    let committed = false;
    try {
      const idempotencyKey = transferIdempotencyKey.current
        ?? request.idempotencyKey
        ?? `ui-${crypto.randomUUID()}`;
      transferIdempotencyKey.current = idempotencyKey;
      await billingApi.createBillingTransfer({
        application_id: applicationId,
        currency,
        amount_minor: amountMinor,
        direction: transferDirection,
        idempotency_key: idempotencyKey
      }, { signal: request.signal, idempotencyKey });
      if (!requestGuard.isCurrent(request)) return;
      const nextWallets = await billingApi.listBillingWallets({ signal: request.signal, force: true });
      if (!requestGuard.isCurrent(request)) return;
      transferIdempotencyKey.current = null;
      setTransferAmount("");
      setWallets(nextWallets);
      setFeedback(copy.saved);
      committed = true;
    } catch {
      if (requestGuard.isCurrent(request)) setFeedback(copy.saveFailed);
    } finally {
      if (requestGuard.isCurrent(request)) setTransferSaving(false);
      requestGuard.finish(request, committed);
    }
  }

  if (loading) return <div className="loading-state" role="status">{copy.saving}</div>;
  if (error) return <div className="error" role="alert">{error}<button type="button" onClick={() => setReloadToken((current) => current + 1)}>{copy.retry}</button></div>;
  if (!settings) return <p className="muted">{copy.loadFailed}</p>;

  const walletCurrencies = Array.from(new Set([
    ...settings.supported_currencies,
    ...walletView.currencies
  ])).sort();
  const applicationWallets = walletView.applicationWalletsFor(applicationId);
  const globalWallets = walletView.globalWallets;

  return (
    <div className="application-module-content">
      <ModuleHeader icon={<Coins size={19} />} title={copy.billing} description={copy.billingHint} />
      <div className="authorization-subsection">
        <Toggle label={copy.acceptSignetBalance} hint={copy.acceptSignetBalanceHint} checked={settings.accept_signet_balance} onChange={(value) => {
          setSettings((current) => current ? { ...current, accept_signet_balance: value } : current);
          onEnabledChange(value);
        }} disabled={!canManage || saving} />
        <label className="application-input">
          <span>{copy.walletMode}</span>
          <select value={settings.wallet_mode} disabled={!canManage || saving || settings.mode_locked_at !== null} onChange={(event) => setSettings((current) => current ? { ...current, wallet_mode: event.target.value as ApplicationBillingSettings["wallet_mode"] } : current)}>
            <option value="shared">{copy.sharedWallet}</option>
            <option value="isolated">{copy.isolatedWallet}</option>
          </select>
          <small>{settings.mode_locked_at !== null ? copy.walletModeLocked : copy.billingHint}</small>
        </label>
        <Input label={copy.billingCurrencies} hint={copy.billingCurrenciesHint} value={settings.supported_currencies.join(", ")} disabled={!canManage || saving} onChange={(value) => setSettings((current) => current ? { ...current, supported_currencies: Array.from(new Set(value.split(",").map((item) => item.trim().toUpperCase()).filter(Boolean))) } : current)} />
      </div>
      <section className="application-wallet-panel">
        <div className="subsection-heading"><div><strong>{copy.walletOverview}</strong><p className="muted">{copy.walletTransferHint}</p></div><span>{settings.wallet_mode === "isolated" ? copy.isolatedWallet : copy.sharedWallet}</span></div>
        <div className="application-wallet-grid">
          {(settings.wallet_mode === "isolated" ? [...globalWallets, ...applicationWallets] : globalWallets).map((wallet) => <article className="application-wallet-card" key={wallet.id}><span>{wallet.account_kind === "user_application" ? copy.isolatedWallet : copy.sharedWallet} · {wallet.currency}</span><strong>{(wallet.available_minor / 10 ** (wallet.minor_unit ?? 2)).toFixed(wallet.minor_unit ?? 2)}</strong><small>{copy.walletAvailable} · {wallet.currency} · {copy.walletReserved}: {(wallet.reserved_minor / 10 ** (wallet.minor_unit ?? 2)).toFixed(wallet.minor_unit ?? 2)}</small></article>)}
          {settings.wallet_mode === "isolated" && applicationWallets.length === 0 && <p className="muted">{copy.noApplicationWallet}</p>}
        </div>
        {canManage && settings.accept_signet_balance && settings.wallet_mode === "isolated" && <form className="application-wallet-transfer" onSubmit={transfer}><div className="form-grid-2 compact-form-grid"><Input label={copy.transferAmount} type="number" value={transferAmount} required disabled={transferSaving} onChange={setTransferAmount} /><label className="application-input"><span>{copy.billingCurrency}</span><select value={transferCurrency || walletCurrencies[0] || "CNY"} disabled={transferSaving} onChange={(event) => setTransferCurrency(event.target.value)}>{(walletCurrencies.length > 0 ? walletCurrencies : ["CNY"]).map((currency) => <option value={currency} key={currency}>{currency}</option>)}</select></label><label className="application-input"><span>{copy.transferDirection}</span><select value={transferDirection} disabled={transferSaving} onChange={(event) => setTransferDirection(event.target.value as typeof transferDirection)}><option value="to_application">{copy.transferToApplication}</option><option value="from_application">{copy.transferFromApplication}</option></select></label></div><button type="submit" className="secondary-button" disabled={transferSaving}>{transferSaving ? copy.saving : copy.executeTransfer}<ArrowRight size={14} /></button></form>}
      </section>
      {canManage && <ModuleSave saving={saving} feedback={feedback} copy={copy} onSave={() => void saveSettings()} />}
    </div>
  );
}
