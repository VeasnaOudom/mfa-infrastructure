package com.khalibre.keycloak.provider.account;

import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.device.DeviceActivityManager;
import org.keycloak.events.Event;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.representations.account.DeviceRepresentation;

class DeviceDetailService {

  private static final String DETAIL_DEVICE = "device";

  private final KeycloakSession session;

  DeviceDetailService(KeycloakSession session) {
    this.session = session;
  }

  Map<String, String> attachDeviceDetail(Event event) {
    Map<String, String> details =
        event.getDetails() == null ? new LinkedHashMap<>() : new LinkedHashMap<>(event.getDetails());

    String label = resolveDeviceLabel(event);
    if (label == null) {
      details.remove(DETAIL_DEVICE);
    } else {
      details.put(DETAIL_DEVICE, label);
    }

    return details;
  }

  private String resolveDeviceLabel(Event event) {
    if (event == null || event.getRealmId() == null || event.getSessionId() == null) {
      return null;
    }

    RealmModel realm = session.realms().getRealm(event.getRealmId());
    if (realm == null) {
      return null;
    }

    UserSessionModel userSession = session.sessions().getUserSession(realm, event.getSessionId());
    if (userSession == null) {
      return null;
    }

    DeviceRepresentation device = DeviceActivityManager.getCurrentDevice(userSession);
    return toLabel(device);
  }

  private static String toLabel(DeviceRepresentation device) {
    if (device == null) {
      return null;
    }

    String browser = normalizeBrowser(device.getBrowser());
    String os = device.getOs();

    boolean hasBrowser = browser != null && !browser.isBlank();
    boolean hasOs = os != null && !os.isBlank();

    if (hasBrowser && hasOs) {
      return browser + " on " + os;
    }
    if (hasBrowser) {
      return browser;
    }
    if (hasOs) {
      return os;
    }
    return null;
  }

  private static String normalizeBrowser(String browser) {
    if (browser == null) {
      return null;
    }

    String trimmed = browser.trim();
    if (trimmed.isEmpty()) {
      return trimmed;
    }

    int slash = trimmed.indexOf('/');
    if (slash <= 0 || slash == trimmed.length() - 1) {
      return trimmed;
    }

    String version = trimmed.substring(slash + 1);
    if (version.matches("[0-9.]+")) {
      return trimmed.substring(0, slash).trim();
    }
    return trimmed;
  }
}
