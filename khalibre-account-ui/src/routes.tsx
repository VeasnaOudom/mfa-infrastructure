import type { IndexRouteObject, RouteObject } from "react-router-dom";
import { environment } from "./environment";
import {
  Applications,
  ContentComponent,
  DeviceActivity,
  Groups,
  LinkedAccounts,
  Oid4Vci,
  PersonalInfo,
  Resources,
} from "@keycloak/keycloak-account-ui";
import { lazy } from "react";

// Lazy so the react-table chunk is only downloaded when the page is opened.
const AccountActivities = lazy(() =>
  import("./pages/AccountActivities.tsx").then((m) => ({ default: m.AccountActivities })),
);

// The MFA channel management page. Also lazy, and separately, so the QR library it pulls in is not
// on the critical path for every account console page.
const MfaChannels = lazy(() =>
  import("./pages/MfaChannels.tsx").then((m) => ({ default: m.MfaChannels })),
);

export const AccountActivitiesRoute: RouteObject = {
  path: "account-security/account-activities",
  element: <AccountActivities />,
};

export const DeviceActivityRoute: RouteObject = {
  path: "account-security/device-activity",
  element: <DeviceActivity />,
};

export const LinkedAccountsRoute: RouteObject = {
  path: "account-security/linked-accounts",
  element: <LinkedAccounts />,
};

export const SigningInRoute: RouteObject = {
  path: "account-security/signing-in",
  element: <MfaChannels />,
};

export const ApplicationsRoute: RouteObject = {
  path: "applications",
  element: <Applications />,
};

export const GroupsRoute: RouteObject = {
  path: "groups",
  element: <Groups />,
};

export const ResourcesRoute: RouteObject = {
  path: "resources",
  element: <Resources />,
};

export const ContentRoute: RouteObject = {
  path: "content/:componentId",
  element: <ContentComponent />,
};

export const PersonalInfoRoute: IndexRouteObject = {
  index: true,
  element: <PersonalInfo />,
  path: "",
};

export const Oid4VciRoute: RouteObject = {
  path: "oid4vci",
  element: <Oid4Vci />,
};

export const routes: RouteObject[] = [
  PersonalInfoRoute,
  DeviceActivityRoute,
  LinkedAccountsRoute,
  SigningInRoute,
  ApplicationsRoute,
  GroupsRoute,
  ResourcesRoute,
  ContentRoute,
  AccountActivitiesRoute,
  ...(environment.features.isOid4VciEnabled ? [Oid4VciRoute] : []),
];