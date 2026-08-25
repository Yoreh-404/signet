import {
  arrayResponse,
  objectResponse,
  pathSegment,
  readCached,
  writeJson
} from "./transport";
import type { ApiMutationOptions, CachedReadOptions } from "./transport";
import type {
  BillingCheckout,
  BillingProvider,
  BillingRecharge,
  BillingTransaction,
  BillingWallet
} from "../../types";

export const BILLING_WALLETS_PATH = "/api/me/billing/wallets";
export const BILLING_PROVIDERS_PATH = "/api/me/billing/providers";
export const BILLING_TRANSACTIONS_PATH = "/api/me/billing/transactions";
export const BILLING_RECHARGES_PATH = "/api/me/billing/recharges";
export const BILLING_TRANSFERS_PATH = "/api/me/billing/transfers";

type ReadOptions = Pick<CachedReadOptions, "force" | "minRevalidateMs" | "signal">;
type MutationOptions = ApiMutationOptions;

export type BillingWorkspaceQuery = {
  wallets: BillingWallet[];
  providers: BillingProvider[];
  transactions: BillingTransaction[];
  recharges: BillingRecharge[];
};

export type BillingWalletViewModel = {
  wallets: BillingWallet[];
  currencies: string[];
  globalWallets: BillingWallet[];
  applicationWalletsFor: (applicationId: string) => BillingWallet[];
  find: (
    accountKind: BillingWallet["account_kind"],
    applicationId?: string,
    currency?: string
  ) => BillingWallet | null;
  minorUnitFor: (currency: string) => number;
};

export function createBillingWalletViewModel(wallets: BillingWallet[]): BillingWalletViewModel {
  const currencyMinorUnits = new Map(
    wallets.map((wallet) => [wallet.currency, wallet.minor_unit ?? 2])
  );
  return {
    wallets,
    currencies: Array.from(new Set(wallets.map((wallet) => wallet.currency))).sort(),
    globalWallets: wallets.filter((wallet) => wallet.account_kind === "user_global"),
    applicationWalletsFor: (applicationId) => wallets.filter((wallet) => (
      wallet.account_kind === "user_application" && wallet.application_id === applicationId
    )),
    find: (accountKind, applicationId, currency) => wallets.find((wallet) => (
      wallet.account_kind === accountKind
      && (accountKind !== "user_application" || wallet.application_id === applicationId)
      && (currency === undefined || wallet.currency === currency)
    )) ?? null,
    minorUnitFor: (currency) => currencyMinorUnits.get(currency) ?? 2
  };
}

export type BillingRechargeInput = {
  amount_minor: number;
  currency: string;
  provider_slug: string;
  idempotency_key: string;
};

export type BillingTransferInput = {
  application_id: string;
  direction: "to_application" | "from_application";
  currency: string;
  amount_minor: number;
  idempotency_key: string;
};

export function listBillingWallets(options?: ReadOptions): Promise<BillingWallet[]> {
  return readCached<BillingWallet[]>(BILLING_WALLETS_PATH, options, arrayResponse);
}

export function listBillingProviders(options?: ReadOptions): Promise<BillingProvider[]> {
  return readCached<BillingProvider[]>(BILLING_PROVIDERS_PATH, options, arrayResponse);
}

export function listBillingTransactions(options?: ReadOptions): Promise<BillingTransaction[]> {
  return readCached<BillingTransaction[]>(BILLING_TRANSACTIONS_PATH, options, arrayResponse);
}

export function listBillingRecharges(options?: ReadOptions): Promise<BillingRecharge[]> {
  return readCached<BillingRecharge[]>(BILLING_RECHARGES_PATH, options, arrayResponse);
}

export function listBillingWorkspace(options?: ReadOptions): Promise<BillingWorkspaceQuery> {
  return Promise.all([
    listBillingWallets(options),
    listBillingProviders(options),
    listBillingTransactions(options),
    listBillingRecharges(options)
  ]).then(([wallets, providers, transactions, recharges]) => ({
    wallets,
    providers,
    transactions,
    recharges
  }));
}

export function billingRechargePath(orderId: string): string {
  return `${BILLING_RECHARGES_PATH}/${pathSegment(orderId)}`;
}

export function billingRechargeQueryPath(orderId: string): string {
  return `${billingRechargePath(orderId)}/query`;
}

export function getBillingRecharge(
  orderId: string,
  options?: ReadOptions
): Promise<BillingRecharge> {
  return readCached<BillingRecharge>(billingRechargePath(orderId), options, objectResponse);
}

/** Reconciles one provider order; callers should poll this endpoint, not the entire history. */
export function queryBillingRecharge(
  orderId: string,
  options?: MutationOptions
): Promise<BillingRecharge> {
  return writeJson<BillingRecharge, undefined>(
    billingRechargeQueryPath(orderId),
    "POST",
    undefined,
    options,
    objectResponse
  );
}

export function createBillingRecharge(
  input: BillingRechargeInput,
  options?: MutationOptions
): Promise<BillingCheckout> {
  return writeJson<BillingCheckout, BillingRechargeInput>(
    BILLING_RECHARGES_PATH,
    "POST",
    input,
    options,
    objectResponse
  );
}

export function createBillingTransfer(
  input: BillingTransferInput,
  options?: MutationOptions
): Promise<void> {
  return writeJson<void, BillingTransferInput>(BILLING_TRANSFERS_PATH, "POST", input, options);
}
