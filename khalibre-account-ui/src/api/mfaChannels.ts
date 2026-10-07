import type { KeycloakContext } from "@keycloak/keycloak-ui-shared";
import { AccountEnvironment } from "@keycloak/keycloak-account-ui";

/** The four channels a user can turn on or off, named as the server names them. */
export type ChannelId = "telegram" | "totp" | "email" | "backupCode";

/** Per-channel state. `since` and `count` are absent when privacyIDEA did not report them. */
export type ChannelState = {
  active: boolean;
  label?: string;
  since?: string;
  count?: number;
};

/** Response of GET /edc-mfa-settings/channels. */
export type MfaChannels = {
  telegram: ChannelState;
  totp: ChannelState;
  email: ChannelState;
  backupCode: ChannelState;
  /** Channels that could be turned on right now. Empty when the user has them all. */
  available: ChannelId[];
  /**
   * False when privacyIDEA could not be reached. The channel flags are then unreliable, so the page
   * says the state is unknown instead of offering changes on top of a guess.
   */
  reachable: boolean;
  enrolmentRequired: boolean;
  telegramConfigured: boolean;
  emailAddressOnFile: boolean;
};

/** What POST /channels/{id}/start returns, per channel. */
export type StartResult = {
  channel: ChannelId;
  /** totp: the otpauth:// URI to draw as a QR. */
  enrolmentUri?: string;
  /** telegram: the bot deeplink to scan. */
  deepLink?: string;
  botUsername?: string;
  /** email: the masked address the code was sent to. */
  label?: string;
  codeLength?: number;
  expiresInMinutes?: number;
};

export type TelegramScan = {
  /** NO_SCAN when nothing was ever written, EXPIRED when the scan aged out. */
  status: string;
  scanned: boolean;
  phoneRequested: boolean;
};

/**
 * Carried on a rejected call so the page can say what actually went wrong.
 *
 * `code` matters more than `status`: the Telegram verify endpoint answers 409 both for "not scanned
 * yet" - where waiting is correct - and for "that Telegram account belongs to someone else", where
 * waiting is hopeless. The status alone cannot tell those apart.
 */
export type MfaApiError = Error & { status?: number; code?: string };

export type BackupCodes = { codes: string[]; count: number };

const BASE = "edc-mfa-settings";

/**
 * Calls the self-service MFA settings endpoint mounted on this realm.
 *
 * <p>Written against {@link fetch} directly rather than the shared `request` helper, which builds
 * URLs under `/realms/{realm}/account/...` — Keycloak's own account REST namespace. These endpoints
 * are a separate realm resource provider and are not mounted there.
 */
async function call<T>(
  { environment, keycloak }: KeycloakContext<AccountEnvironment>,
  path: string,
  init: { method?: "POST" | "PUT" | "DELETE"; body?: unknown; signal?: AbortSignal } = {},
): Promise<T> {
  try {
    await keycloak.updateToken(5);
  } catch {
    await keycloak.login();
  }

  const response = await fetch(
    new URL(
      `${environment.serverBaseUrl}/realms/${environment.realm}/${BASE}/${path}`,
    ),
    {
      signal: init.signal,
      // Never let the browser answer a poll from its cache. The server sends `Cache-Control:
      // no-store`, but this is the endpoint the account console hits every two seconds, and a single
      // replayed answer here is indistinguishable from a broken scan: the page reported an expired
      // QR while a fresh one was sitting on the server. Belt and braces, and it costs nothing.
      cache: "no-store",
      method: init.method ?? "GET",
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      headers: {
        "Content-Type": "application/json",
        authorization: `Bearer ${keycloak.token}`,
      },
    },
  );

  if (!response.ok) {
    // The server sends a human-readable `error` on every failure it can describe, which is far more
    // useful than the bare status code — "That Telegram account is already linked to another user"
    // and 409 are not the same thing to show a user.
    const detail = await response.json().catch(() => null);
    const error = new Error(
      (detail && (detail as { error?: string }).error) ||
        `Request failed: ${response.status}`,
    ) as MfaApiError;
    error.status = response.status;
    error.code = detail && (detail as { code?: string }).code;
    throw error;
  }

  return (await response.json()) as T;
}

export const fetchMfaChannels = (context: KeycloakContext<AccountEnvironment>, signal?: AbortSignal) =>
  call<MfaChannels>(context, "channels", { signal });

export const removeChannel = (
  context: KeycloakContext<AccountEnvironment>,
  channel: ChannelId,
) =>
  call<{ channel: ChannelId; removed: boolean; willNeedEnrolment: boolean }>(
    context,
    `channels/${channel}/remove`,
    { method: "POST" },
  );

export const startChannel = (
  context: KeycloakContext<AccountEnvironment>,
  channel: ChannelId,
) => call<StartResult>(context, `channels/${channel}/start`, { method: "POST" });

export const verifyChannel = (
  context: KeycloakContext<AccountEnvironment>,
  channel: ChannelId,
  code: string,
) => call<{ status: string; channel: ChannelId }>(context, `channels/${channel}/verify`, {
  method: "POST",
  body: { code },
});

/**
 * Telegram needs no code, so its verify step takes none and applies whatever the scan produced.
 */
export const verifyTelegram = (context: KeycloakContext<AccountEnvironment>) =>
  call<{ status: string; channel: ChannelId }>(context, "channels/telegram/verify", {
    method: "POST",
    body: {},
  });

export const pollTelegramScan = (
  context: KeycloakContext<AccountEnvironment>,
  signal?: AbortSignal,
) => call<TelegramScan>(context, "channels/telegram/scan", { signal });

export const regenerateBackupCodes = (context: KeycloakContext<AccountEnvironment>) =>
  call<BackupCodes>(context, "channels/backupCode/regenerate", { method: "POST" });

/** Human label for a channel, used in confirmations and errors. */
export const channelName = (channel: ChannelId, t: (key: string) => string) =>
  t(`mfaChannel.${channel}`);