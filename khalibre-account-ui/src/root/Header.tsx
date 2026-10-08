import { useEnvironment } from "@keycloak/keycloak-account-ui";
import {
  Dropdown,
  DropdownItem,
  DropdownList,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadMain,
  MastheadToggle,
  MenuToggle,
  MenuToggleElement,
  PageContext,
  Toolbar,
  ToolbarContent,
  ToolbarGroup,
  ToolbarItem,
} from "@patternfly/react-core";
import { BarsIcon, ExternalLinkAltIcon } from "@patternfly/react-icons";
import { MouseEvent, useContext, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import brandLogo from "../img/edc-logo-white.png";

import { joinPath } from "../utils/joinPath";

import style from "./header.module.css";

export const Header = () => {
  const {environment, keycloak} = useEnvironment();
  const {t} = useTranslation();
  const {onSidebarToggle} = useContext(PageContext);
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);

  const username = useMemo(() => {
    const parsed = keycloak.tokenParsed as
      | { preferred_username?: string; name?: string }
      | undefined;
    return parsed?.preferred_username || parsed?.name || "User";
  }, [keycloak.tokenParsed]);
  const userInitials = useMemo(() => {
    const parts = username
      .trim()
      .split(/\s+/)
      .filter(Boolean);

    if (parts.length === 0) {
      return "U";
    }

    if (parts.length === 1) {
      return parts[0][0].toUpperCase();
    }

    return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
  }, [username]);
  const adminConsoleUrl = joinPath(
    environment.serverBaseUrl,
    `/admin/${environment.realm}/console/`,
  );
  const accountConsoleUrl = joinPath(
    environment.serverBaseUrl,
    `/realms/${environment.realm}/account/`,
  );
  const isAdmin = useMemo(() => {
    const parsed = keycloak.tokenParsed as
      | {
          realm_access?: { roles?: string[] };
          resource_access?: Record<string, { roles?: string[] }>;
        }
      | undefined;
    const realmRoles = new Set(parsed?.realm_access?.roles || []);
    const realmManagementRoles = new Set(
      parsed?.resource_access?.["realm-management"]?.roles || [],
    );

    return (
      keycloak.hasRealmRole("admin") ||
      keycloak.hasRealmRole("manage-realm") ||
      keycloak.hasResourceRole("realm-admin", "realm-management") ||
      keycloak.hasResourceRole("manage-realm", "realm-management") ||
      realmRoles.has("admin") ||
      realmRoles.has("manage-realm") ||
      realmManagementRoles.has("realm-admin") ||
      realmManagementRoles.has("manage-realm")
    );
  }, [keycloak, keycloak.tokenParsed]);

  const handleClickCapture = (event: MouseEvent<HTMLButtonElement>) => {
    const target = event.target as HTMLElement;
    if (target.closest("#nav-toggle")) {
      onSidebarToggle();
    }
  };

  const handleLogout = async () => {
    await keycloak.logout();
  };

  return (
    <Masthead className={style.masthead} data-testid="page-header">
      <MastheadMain>
        <MastheadToggle>
          <button
            id="nav-toggle"
            type="button"
            className={style.navToggle}
            aria-label={t("toggleNavigation")}
            onClick={handleClickCapture}
          >
            <BarsIcon/>
          </button>
        </MastheadToggle>
        <MastheadBrand>
          <a href={accountConsoleUrl} className={style.brandLink}>
            <img
              src={brandLogo}
              alt={t("logo")}
              className={style.brand}
            />
            <span className={style.brandText}>EDC Identity</span>
            <span className={style.brandSubText}>Account Console</span>
          </a>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Toolbar isStatic>
          <ToolbarContent>
            <ToolbarGroup>
              {isAdmin && (
                <ToolbarItem>
                  <a
                    href={adminConsoleUrl}
                    className={style.adminConsoleLink}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <span>
                      {t("securityAdminConsole", {
                        defaultValue: "Security Admin Console",
                      })}
                    </span>
                    <ExternalLinkAltIcon className={style.adminConsoleIcon}/>
                  </a>
                </ToolbarItem>
              )}
              <ToolbarItem>
                <Dropdown
                  isOpen={isDropdownOpen}
                  onOpenChange={(open) => setIsDropdownOpen(open)}
                  toggle={(toggleRef: React.Ref<MenuToggleElement>) => (
                    <MenuToggle
                      ref={toggleRef}
                      onClick={() => setIsDropdownOpen((open) => !open)}
                    >
                      <span className={style.initialsBadge}>{userInitials}</span>
                      <span className={style.username}>{username}</span>
                    </MenuToggle>
                  )}
                  shouldFocusToggleOnSelect
                >
                  <DropdownList>
                    <DropdownItem key="logout" onClick={handleLogout}>
                      {t("eventType.info.LOGOUT", {defaultValue: "Sign out"})}
                    </DropdownItem>
                  </DropdownList>
                </Dropdown>
              </ToolbarItem>
            </ToolbarGroup>
          </ToolbarContent>
        </Toolbar>
      </MastheadContent>
    </Masthead>
  );
};