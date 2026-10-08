import type { KeycloakContext } from "@keycloak/keycloak-ui-shared";
import { AccountEnvironment } from "@keycloak/keycloak-account-ui";

/** The event types the "Account activities" page knows how to describe. */
export type EventType =
    | "LOGIN"
    | "LOGIN_ERROR"
    | "LOGOUT"
    | "LOGOUT_ERROR"
    | "CODE_TO_TOKEN"
    | "CODE_TO_TOKEN_ERROR"
    | "REFRESH_TOKEN"
    | "REFRESH_TOKEN_ERROR"
    | "IDENTITY_PROVIDER_LOGIN"
    | "IDENTITY_PROVIDER_LOGIN_ERROR"
    | "IDENTITY_PROVIDER_FIRST_LOGIN"
    | "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR"
    | "IDENTITY_PROVIDER_LINK_ACCOUNT"
    | "IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR"
    | "FEDERATED_IDENTITY_LINK"
    | "FEDERATED_IDENTITY_LINK_ERROR"
    | "REMOVE_FEDERATED_IDENTITY"
    | "REMOVE_FEDERATED_IDENTITY_ERROR"
    | "UPDATE_PASSWORD"
    | "UPDATE_PASSWORD_ERROR"
    | "UPDATE_CREDENTIAL"
    | "UPDATE_CREDENTIAL_ERROR"
    | "REMOVE_CREDENTIAL"
    | "REMOVE_CREDENTIAL_ERROR"
    | "UPDATE_TOTP"
    | "UPDATE_TOTP_ERROR"
    | "REMOVE_TOTP"
    | "REMOVE_TOTP_ERROR"
    | "UPDATE_EMAIL"
    | "UPDATE_EMAIL_ERROR"
    | "UPDATE_PROFILE"
    | "UPDATE_PROFILE_ERROR"
    | "VERIFY_EMAIL"
    | "VERIFY_EMAIL_ERROR"
    | "VERIFY_PROFILE"
    | "VERIFY_PROFILE_ERROR"
    | "GRANT_CONSENT"
    | "GRANT_CONSENT_ERROR"
    | "REVOKE_GRANT"
    | "REVOKE_GRANT_ERROR"
    | "SEND_RESET_PASSWORD"
    | "SEND_RESET_PASSWORD_ERROR"
    | "RESET_PASSWORD"
    | "RESET_PASSWORD_ERROR"
    | "REGISTER"
    | "REGISTER_ERROR"
    | "DELETE_ACCOUNT"
    | "DELETE_ACCOUNT_ERROR";

/** All event types the "Account activities" page can filter on. */
export const ALL_EVENT_TYPES: EventType[] = [
  "LOGIN",
  "LOGIN_ERROR",
  "LOGOUT",
  "LOGOUT_ERROR",
  "CODE_TO_TOKEN",
  "CODE_TO_TOKEN_ERROR",
  "REFRESH_TOKEN",
  "REFRESH_TOKEN_ERROR",
  "IDENTITY_PROVIDER_LOGIN",
  "IDENTITY_PROVIDER_LOGIN_ERROR",
  "IDENTITY_PROVIDER_FIRST_LOGIN",
  "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR",
  "IDENTITY_PROVIDER_LINK_ACCOUNT",
  "IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR",
  "FEDERATED_IDENTITY_LINK",
  "FEDERATED_IDENTITY_LINK_ERROR",
  "REMOVE_FEDERATED_IDENTITY",
  "REMOVE_FEDERATED_IDENTITY_ERROR",
  "UPDATE_PASSWORD",
  "UPDATE_PASSWORD_ERROR",
  "UPDATE_CREDENTIAL",
  "UPDATE_CREDENTIAL_ERROR",
  "REMOVE_CREDENTIAL",
  "REMOVE_CREDENTIAL_ERROR",
  "UPDATE_TOTP",
  "UPDATE_TOTP_ERROR",
  "REMOVE_TOTP",
  "REMOVE_TOTP_ERROR",
  "UPDATE_EMAIL",
  "UPDATE_EMAIL_ERROR",
  "UPDATE_PROFILE",
  "UPDATE_PROFILE_ERROR",
  "VERIFY_EMAIL",
  "VERIFY_EMAIL_ERROR",
  "VERIFY_PROFILE",
  "VERIFY_PROFILE_ERROR",
  "GRANT_CONSENT",
  "GRANT_CONSENT_ERROR",
  "REVOKE_GRANT",
  "REVOKE_GRANT_ERROR",
  "SEND_RESET_PASSWORD",
  "SEND_RESET_PASSWORD_ERROR",
  "RESET_PASSWORD",
  "RESET_PASSWORD_ERROR",
  "REGISTER",
  "REGISTER_ERROR",
  "DELETE_ACCOUNT",
  "DELETE_ACCOUNT_ERROR",
];

export type AccountActivity = {
  time: number;
  type: EventType | string;
  clientId?: string;
  ipAddress?: string;
  error?: string;
  details?: Record<string, string>;
};

export type AccountActivitiesResponse = {
  first: number;
  max: number;
  events: AccountActivity[];
};

type Translator = (key: string, options?: { defaultValue?: string }) => string;

const isErrorType = (type: string) => type.endsWith("_ERROR");

/**
 * Returns the translation key for an event type, e.g. `eventType.LOGIN` for `LOGIN`. Unmapped
 * types fall back to a readable version of the raw name so new server-side event types still
 * render something sensible.
 */
export const eventTypeKey = (type: string) =>
  `eventType.${isErrorType(type) ? "error" : "info"}.${type}`;

export const eventTypeFallback = (type: string) =>
  type
  .toLowerCase()
  .split("_")
  .map((part, index) =>
    index === 0 ? part.charAt(0).toUpperCase() + part.slice(1) : part,
  )
  .join(" ");

const titleCase = (value: string) =>
  value
    .split(/[_\s-]+/)
    .filter((entry) => entry.length > 0)
    .map((entry) => entry.charAt(0).toUpperCase() + entry.slice(1).toLowerCase())
    .join(" ");

const channelFrom = (activity: AccountActivity) => activity.details?.mfa_channel;

const methodKeyFromChannel = (channel?: string) => {
  switch (channel) {
    case "telegram":
      return "accountActivitiesMethodTelegram";
    case "totp":
      return "accountActivitiesMethodAuthenticatorApp";
    case "email":
      return "accountActivitiesMethodEmail";
    case "backupCode":
      return "accountActivitiesMethodBackupCode";
    default:
      return undefined;
  }
};

export const getActivityLabel = (
  activity: AccountActivity,
  t: Translator,
): string => {
  const channel = channelFrom(activity);

  switch (activity.type) {
    case "CLIENT_INITIATED_ACCOUNT_LINKING":
      return t("accountActivitiesMappedInitiateLinkTelegram");
    case "FEDERATED_IDENTITY_LINK":
      return channel === "telegram"
        ? t("accountActivitiesMappedTelegramAdded")
        : t("accountActivitiesMappedTelegramLinked");
    case "REMOVE_FEDERATED_IDENTITY":
      return channel === "telegram"
        ? t("accountActivitiesMappedTelegramRemoved")
        : t("accountActivitiesMappedTelegramUnlinked");
    case "UPDATE_EMAIL":
      return t("accountActivitiesMappedEmailAdded");
    default:
      return t(eventTypeKey(activity.type), {
        defaultValue: eventTypeFallback(activity.type),
      });
  }
};

export const getMethodLabel = (
  activity: AccountActivity,
  t: Translator,
): string => {
  const methodFromChannel = methodKeyFromChannel(channelFrom(activity));
  if (methodFromChannel) {
    return t(methodFromChannel);
  }

  const identityProvider = activity.details?.identity_provider;
  if (identityProvider != null && identityProvider.trim() !== "") {
    return titleCase(identityProvider);
  }

  if (activity.type === "LOGIN" || activity.type === "LOGIN_ERROR") {
    return t("accountActivitiesMethodPassword");
  }

  return t("accountActivitiesMethodAccountConsole");
};

/** Server-side filters supported by the account activities endpoint. */
export type AccountActivitiesFilter = {
  type?: string[];
  dateFrom?: string;
  dateTo?: string;
  ipAddress?: string;
};

export const fetchAccountActivities = async (
  {environment, keycloak}: KeycloakContext<AccountEnvironment>,
  {
    first,
    max,
    filter,
    signal,
  }: {
    first: number;
    max: number;
    filter?: AccountActivitiesFilter;
    signal?: AbortSignal;
  },
): Promise<AccountActivitiesResponse> => {
  try {
    await keycloak.updateToken(5);
  } catch {
    await keycloak.login();
  }

  const url = new URL(
    `${environment.serverBaseUrl}/realms/${environment.realm}/account-activities/events`,
  );
  url.searchParams.set("first", `${first}`);
  url.searchParams.set("max", `${max}`);

  for (const type of filter?.type ?? []) {
    url.searchParams.append("type", type);
  }
  if (filter?.dateFrom) {
    url.searchParams.set("dateFrom", filter.dateFrom);
  }
  if (filter?.dateTo) {
    url.searchParams.set("dateTo", filter.dateTo);
  }
  if (filter?.ipAddress) {
    url.searchParams.set("ipAddress", filter.ipAddress);
  }

  const response = await fetch(url, {
    signal,
    headers: {
      "Content-Type": "application/json",
      authorization: `Bearer ${keycloak.token}`,
    },
  });

  if (!response.ok) {
    throw new Error(
      `Failed to load account activities: ${response.status}`,
    );
  }

  return response.json();
};
