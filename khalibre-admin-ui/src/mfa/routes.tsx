import { lazy } from "react";
import type { TFunction } from "i18next";

/**
 * The EDC MFA page, added to the admin console by scripts/patch-admin-ui.mjs.
 *
 * This file is copied into the upstream tree at build time (as `src/khalibre/routes.tsx`) and
 * spread into the console's route array. It lives out of the checkout so an upgrade is a diff here
 * rather than a merge conflict against a file we do not own.
 *
 * The route is a plain object, as every other route in the console is: there is no
 * `toCreateReactRoute` helper in 26.x, and `handle.access` is what both the router's AuthWall and the
 * sidebar read. `manage-realm` is the one that matters, because the endpoint behind the page refuses
 * anything else - a page that renders and then 401s would be worse than one that is not offered.
 *
 * Two segments after the realm would be unambiguous against the dashboard's `/:realm/:tab`; this one
 * is static and React Router ranks static segments above dynamic ones, which is why it wins.
 */
const MfaChannels = lazy(() => import("./MfaChannels"));

export const EdcMfaRoute = {
  path: "/:realm/edc-mfa",
  element: <MfaChannels />,
  breadcrumb: (t: TFunction) => t("edcMfaChannels"),
  handle: {
    // A literal type, not a widened `string`: the console's route type unions the access types, and
    // a widened string would not be assignable when this array is spread into it.
    access: "manage-realm" as const,
  },
};

const routes = [EdcMfaRoute];

export default routes;