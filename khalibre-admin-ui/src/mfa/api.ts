import { fetchWithError } from "@keycloak/keycloak-admin-client";
import { getErrorDescription, getErrorMessage } from "@keycloak/keycloak-ui-shared";

/**
 * The realm resource provider this page drives, on the server side.
 *
 * The path is fixed by the provider's factory id (`edc-mfa-admin`), and it is mounted on the realm,
 * so it is the realm's own admin token that has to authorise the call - never the master realm's.
 * See EdcMfaAdminResource for the other half of that rule.
 */
const MOUNT = "edc-mfa-admin";

/**
 * The channels this page offers.
 *
 * <p>Backup codes are absent by design: privacyIDEA issues them when a user enrols on one of these
 * three, so there is nothing for an administrator to decide about them. The server still reports and
 * honours a policy for them, because `EdcChannelPolicy` names four channels and the account console
 * needs to know a backup-code policy in force - but a control here that cannot express it would be a
 * control that lies.
 */
export const CHANNEL_NAMES = ["email", "telegram", "totp"] as const;

export type ChannelName = (typeof CHANNEL_NAMES)[number];

export type ChannelState = {
  channel: ChannelName;
  enabled: boolean;
  /** Whether a user must have this channel set up. Never true while `enabled` is false. */
  required: boolean;
};

export type ApplicationPolicy = {
  clientId: string;
  name: string;
  inherited: boolean;
  enabledAttribute: string | null;
  requiredAttribute: string | null;
  channels: ChannelState[];
  lastChanged: string | null;
};

export type ChannelsResponse = {
  /** The realm attributes holding the policy, so the page can show what it just wrote. */
  attribute: string;
  attributeRequired: string;
  /** Whether the Telegram bot has a token at all - a different fact from the policy. */
  telegramConfigured: boolean;
  default: {
    channels: ChannelState[];
  };
  applications: ApplicationPolicy[];
};

/** Everything the calls need. Passed in rather than imported, so this file stays React-free. */
export type AdminApi = {
  /**
   * `environment.serverBaseUrl` - the **server** root, not the admin console's.
   *
   * A realm resource provider is mounted at `/realms/{realm}/…`, and it is *not* reachable under
   * `/admin/realms/{realm}/…`: `AdminRoot` and `RealmAdminResource` answer from a fixed list of
   * resources and never consult the realm's provider factories, so that shape answers 404 whatever
   * token it carries. Measured, and it is silent - a wrong base here looks exactly like a provider
   * that was never deployed. So the console's own `fetchAdminUI` idiom is not the model to copy.
   */
  serverBaseUrl: string;
  /** The realm being administered, unencoded. */
  realm: string;
  /** Returns a live admin access token. Called per request, never cached. */
  getToken: () => Promise<string>;
};

/**
 * The provider's URL under the server's own root.
 *
 * `serverBaseUrl` is documented as normalised without a trailing slash, but a leading one is not
 * guaranteed and a doubled slash here is a 404 that reads like a missing provider, so both ends are
 * trimmed rather than trusted.
 */
function endpoint(api: AdminApi, path: string, query?: Record<string, string>): string {
  const base = api.serverBaseUrl.replace(/\/+$/, "");
  const url = `${base}/realms/${encodeURIComponent(api.realm)}/${MOUNT}/${path}`;
  return query ? `${url}?${new URLSearchParams(query)}` : url;
}

/** One authenticated request. The token is fetched per call because the console's copy expires. */
async function authorized(
  api: AdminApi,
  path: string,
  init: RequestInit,
  query?: Record<string, string>,
): Promise<Response> {
  const token = await api.getToken();
  return await fetchWithError(endpoint(api, path, query), {
    ...init,
    headers: {
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init.headers,
    },
  });
}

/**
 * Reads the current policy.
 *
 * The rows are validated rather than cast: the response is our own provider's, but a channel name
 * this build has never heard of should not reach a `switch` as if it were one of ours, and a
 * missing row must not silently read as "off".
 */
export async function fetchChannels(api: AdminApi): Promise<ChannelsResponse> {
  const response = await authorized(api, "channels", { method: "GET" });
  const body = (await response.json()) as any;
  const parseRows = (rows: any[]): ChannelState[] => {
    const list = Array.isArray(rows) ? rows : [];
    return CHANNEL_NAMES.map((name) => {
      const row = list.find((candidate) => candidate?.channel === name);
      return {
        channel: name,
        enabled: list.some((candidate) => candidate?.channel === name && candidate.enabled === true),
        required: list.some((candidate) => candidate?.channel === name && candidate.required === true),
      };
    });
  };

  const defaultChannels = parseRows(body.default?.channels || body.channels);
  const applications: ApplicationPolicy[] = Array.isArray(body.applications)
    ? body.applications.map((app: any) => ({
        clientId: app.clientId,
        name: app.name,
        inherited: app.inherited === true,
        enabledAttribute: app.enabledAttribute ?? null,
        requiredAttribute: app.requiredAttribute ?? null,
        channels: parseRows(app.channels),
        lastChanged: app.lastChanged ?? null,
      }))
    : [];

  return {
    attribute: typeof body.attribute === "string" ? body.attribute : "",
    attributeRequired: typeof body.attributeRequired === "string" ? body.attributeRequired : "",
    telegramConfigured: body.telegramConfigured === true,
    default: { channels: defaultChannels },
    applications,
  };
}

/**
 * Writes the whole policy. The server replaces the set rather than merging it, so this sends every
 * channel with its state - a partial update would make "turn Telegram off" mean something different
 * depending on what was there before.
 *
 * An empty channel list is a refusal, not a write, and this refuses it before sending. The server
 * reads an empty list on a client as "clear the override and inherit", which is the right meaning for
 * the reset button and catastrophic for a save that silently emptied every switch: the application
 * would appear configured in this table and behave as though nobody had ever touched it. One line
 * here, and the two paths it could confuse stay distinguishable.
 */
export async function setChannels(
  api: AdminApi,
  channels: Record<ChannelName, boolean>,
  required: Record<ChannelName, boolean>,
  clientId?: string,
): Promise<ChannelsResponse> {
  const enabled = CHANNEL_NAMES.filter((name) => channels[name]);
  if (clientId && enabled.length === 0) {
    throw new Error("Leave at least one channel switched on");
  }
  const demanded = enabled.filter((name) => required[name]);
  const query: Record<string, string> = {
    channels: enabled.join(","),
    // Only the channels this page offers. The server refuses a required channel that is switched off,
    // so the two are filtered here rather than letting the save fail on a hidden row.
    required: demanded.join(","),
  };
  if (clientId) {
    query.client = clientId;
  }
  const response = await authorized(api, "channels", { method: "POST" }, query);
  await response.json();
  // Re-read rather than trusting the local state: the server canonicalises the list, and the page
  // should show what was stored, not what was asked for.
  return await fetchChannels(api);
}

/**
 * Drops an application's own policy so it inherits the realm default again.
 *
 * Named separately from {@link setChannels} on purpose: this is the one call that legitimately sends
 * an empty channel list, and keeping it apart is what stops "switch everything off" and "go back to
 * inheriting" from being the same request.
 */
export async function clearClientPolicy(
  api: AdminApi,
  clientId: string,
): Promise<ChannelsResponse> {
  const response = await authorized(api, "channels", { method: "POST" }, {
    client: clientId,
    channels: "",
  });
  await response.json();
  return await fetchChannels(api);
}

/**
 * A message worth showing the admin.
 *
 * `fetchWithError` throws a `NetworkError`, and the console's own `getErrorMessage` reads the body's
 * `error` field - which is what every refusal on this provider answers with, including the "leave
 * one enabled" conflict, so the reason reaches the admin instead of a generic failure. It throws
 * when it cannot make sense of what it was given, and a throw inside a `catch` would leave the page
 * stuck on a spinner with an unhandled rejection, hence the guard.
 */
export function messageOf(error: unknown): string {
  try {
    return getErrorMessage(error) ?? "";
  } catch {
    return "";
  }
}

/**
 * The provider's extra explanation, when it sent one.
 *
 * Read through the console's `getErrorDescription`, which looks for `error_description` - so the
 * provider writes that field name rather than inventing one.
 */
export function detailOf(error: unknown): string {
  return getErrorDescription(error) ?? "";
}