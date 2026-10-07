package com.khalibre.keycloak.provider.edc;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import com.khalibre.keycloak.provider.privacyIdea.PrivacyIdeaSettings;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;

/**
 * Resets one user's MFA setup, for ICT.
 *
 * <p>Mounted at {@code /realms/{realm}/edc-mfa-admin/} by {@link EdcMfaAdminResourceFactory}.
 *
 * <p>This exists because nothing else can undo a Telegram link on this realm. The {@code telegram-*}
 * and {@code edc-mfa-enrolled-*} attributes are local to an LDAP-federated user, and the admin REST
 * API cannot remove them: the delete reports success, the attribute reads back as gone, and a later
 * sync restores the original value with its original timestamp. An in-process write is the only
 * thing that sticks, and nothing in the product did one - so a link made by the wrong person, or a
 * second account wrongly claimed, had no way out but direct SQL.
 *
 * <p>Authorised on a realm-management token. Deliberately not the account-console token that
 * {@code AccountActivitiesResource} accepts, so an end-user session cannot reach it.
 */
public class EdcMfaAdminResource implements RealmResourceProvider {

  private static final Logger log = Logger.getLogger(EdcMfaAdminResource.class);

  /** Cleared on unlink: the chat id, plus the handle and names kept only to display it. */
  private static final Set<String> TELEGRAM_ATTRIBUTES = Set.of(
      EdcChannelDetector.TELEGRAM_USER_ID_ATTR,
      EdcChannelDetector.TELEGRAM_USERNAME_ATTR,
      EdcChannelDetector.TELEGRAM_FIRST_NAME_ATTR,
      EdcChannelDetector.TELEGRAM_LAST_NAME_ATTR);

  /** Where Keycloak puts realm-management client roles on a token. Spelled out: keycloak-common is
   *  not on this module's compile classpath, and a wrong id here fails closed anyway. */
  private static final String REALM_MANAGEMENT_CLIENT_ID = "realm-management";

  /** Token types a user can hold, so {@code deleteTokens=true} leaves them with no channel at all. */
  private static final String[] TOKEN_TYPES = { "spass", "hotp", "totp", "tan" };

  private final KeycloakSession session;

  public EdcMfaAdminResource(KeycloakSession session) {
    this.session = session;
  }

  /**
   * Puts a user back to having no second step, so their next sign-in runs the wizard from scratch.
   *
   * <p>The enrolment marker is cleared but the required action is <em>kept</em>. Removing it would be
   * a hole: {@code requiresEnrolment} needs the marker to be absent to demand the wizard, so taking
   * the action away at the same time leaves a sign-in where neither the OTP gate nor the wizard
   * runs. Leaving it means the wizard is already queued for that very next login.
   *
   * @param username the account to reset, by username or email
   * @param deleteTokens also delete their privacyIDEA tokens
   * @return what was removed, so the caller can see the effect instead of assuming it
   */
  @POST
  @Path("reset")
  @Produces(MediaType.APPLICATION_JSON)
  public Response reset(@QueryParam("username") String username,
      @QueryParam("deleteTokens") boolean deleteTokens,
      @Context HttpHeaders headers, @Context UriInfo uriInfo) {
    if (!isIct(headers, uriInfo)) {
      log.warn("method=reset status=UNAUTHORIZED message=Needs a realm-management token");
      return Response.status(Response.Status.UNAUTHORIZED)
          .entity(Map.of("error", "Realm management credentials are required",
              "hint", "The token must be issued by this realm and carry manage-realm. A master-realm "
                  + "token will not do: a provider mounted here validates against this realm's keys, "
                  + "and the master admin has no user record here to look up"))
          .build();
    }
    if (username == null || username.isBlank()) {
      return Response.status(Response.Status.BAD_REQUEST)
          .entity(Map.of("error", "username is required")).build();
    }

    RealmModel realm = session.getContext().getRealm();
    UserModel user = session.users().getUserByUsername(realm, username);
    if (user == null) {
      user = session.users().getUserByEmail(realm, username);
    }
    if (user == null) {
      return Response.status(Response.Status.NOT_FOUND)
          .entity(Map.of("error", "No such user")).build();
    }

    Map<String, Object> report = new LinkedHashMap<>();
    report.put("username", user.getUsername());
    report.put("telegramAttributesRemoved", removeAttributes(user, TELEGRAM_ATTRIBUTES));
    report.put("telegramFederatedIdentityRemoved", removeTelegramIdentity(realm, user));

    boolean hadMarker = EdcEnrolmentState.isComplete(user);
    EdcEnrolmentState.clear(session, user);
    report.put("enrolmentMarkerCleared", hadMarker);

    // Ensured, not removed - see the method comment.
    user.addRequiredAction(EdcMfaEnrolmentRequiredAction.PROVIDER_ID);
    report.put("enrolmentActionQueued", true);

    if (deleteTokens) {
      report.put("privacyIdeaTokens", deletePrivacyIdeaTokens(user));
    }

    log.infof("method=reset username=%s report=%s", user.getUsername(), report);
    return Response.ok(report, MediaType.APPLICATION_JSON).build();
  }

  /**
   * Removes attributes in process, which on a federated user is the only thing that survives. The
   * caller runs inside the request transaction, so this commits with the response.
   */
  private boolean removeAttributes(UserModel user, Set<String> names) {
    boolean removed = false;
    for (String name : names) {
      if (user.getFirstAttribute(name) != null) {
        user.removeAttribute(name);
        removed = true;
      }
    }
    return removed;
  }

  private boolean removeTelegramIdentity(RealmModel realm, UserModel user) {
    try {
      return session.users().removeFederatedIdentity(realm, user,
          EdcChannelDetector.TELEGRAM_IDP_ALIAS);
    } catch (Exception e) {
      // Not fatal: the detector reads the attributes, and those are already gone.
      log.warnf("method=removeTelegramIdentity user=%s error=%s", user.getUsername(),
          e.getMessage());
      return false;
    }
  }

  /**
   * Deletes the user's privacyIDEA tokens, leaving them with no channel rather than a token nothing
   * can deliver to. Failures are reported, not thrown: the attributes are already cleared, and a
   * privacyIDEA outage must not make the caller think the whole reset failed.
   */
  private String deletePrivacyIdeaTokens(UserModel user) {
    try {
      PrivacyIdeaSettings.Settings settings = PrivacyIdeaSettings.resolve(session);
      PrivacyIdeaService privacyIdea = new PrivacyIdeaService(settings.baseUrlTrimmed(),
          settings.adminUsername(), settings.adminPassword());
      String adminToken = privacyIdea.getPrivacyIdeaAuthToken();
      if (adminToken == null || adminToken.isBlank()) {
        return "skipped: no privacyIDEA admin token";
      }
      int deleted = 0;
      for (String type : TOKEN_TYPES) {
        int before = privacyIdea.getActiveTokenSerials(user.getUsername(), type, adminToken).size();
        privacyIdea.deleteTokens(user.getUsername(), type, adminToken);
        deleted += before;
      }
      return deleted + " deleted";
    } catch (Exception e) {
      log.warnf("method=deletePrivacyIdeaTokens user=%s error=%s", user.getUsername(),
          e.getMessage());
      return "failed: " + e.getMessage();
    }
  }

   /**
   * Whether the caller is ICT rather than an end user.
   *
   * <p>One rule: realm-management authority in the token, read from both the places it can appear.
   * That is the whole check.
   *
   * <p>An earlier version of this also accepted "the token was issued by a different realm", on the
   * reasoning that the master admin is a legitimate operator here. That branch is gone: a provider
   * mounted on this realm can only validate a token this realm minted, so it could never fire, and
   * code that looks like a privilege check but is not one is worse than no code - it invites a reader
   * to believe the master admin can reach this endpoint. It cannot. Getting a token that can is the
   * caller's problem, and {@code docs/otp-flow-setup.md} says how.
   *
   * <p>An end user satisfies neither: they hold only {@code default-roles-mfa} and no
   * realm-management role.
   */
  private boolean isIct(HttpHeaders headers, UriInfo uriInfo) {
    String tokenString = AppAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
    if (tokenString == null) {
      return false;
    }
    AuthenticationManager.AuthResult authResult =
        new AppAuthManager.BearerTokenAuthenticator(session)
            .setUriInfo(uriInfo)
            .setHeaders(headers)
            .setConnection(session.getContext().getConnection())
            .setTokenString(tokenString)
            .authenticate();
    if (authResult == null || authResult.getToken() == null) {
      return false;
    }
    return hasManageRealm(authResult.getToken());
  }

  /**
   * Whether the token carries realm-management authority.
   *
   * <p>Both places are checked, and both are needed. {@code manage-realm} is a <em>client</em> role
   * of {@code realm-management}, so on a user token it arrives under {@code resource_access}; a
   * service-account token carries the same authority in {@code realm_access}. Checking only the
   * latter rejects ICT; checking only the former rejects automation.
   */
  private boolean hasManageRealm(AccessToken token) {
    return holdsAuthority(token.getRealmAccess())
        || holdsAuthority(token.getResourceAccess(REALM_MANAGEMENT_CLIENT_ID));
  }

  private static boolean holdsAuthority(AccessToken.Access access) {
    Set<String> roles = access == null ? null : access.getRoles();
    return roles != null && (roles.contains("manage-realm") || roles.contains("admin"));
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {
    // Nothing to release.
  }
}
