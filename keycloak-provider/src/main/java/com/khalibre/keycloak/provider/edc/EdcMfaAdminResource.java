package com.khalibre.keycloak.provider.edc;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.GET;
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
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
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

  /** Roles that make an account an ICT one: the composite, or the single role it contains. */
  private static final String[] REALM_ADMIN_ROLES = { "manage-realm", "admin" };

  /** Token types a user can hold, so {@code deleteTokens=true} leaves them with no channel at all. */
  private static final String[] TOKEN_TYPES = { "spass", "hotp", "totp", "tan" };

  private final KeycloakSession session;

  public EdcMfaAdminResource(KeycloakSession session) {
    this.session = session;
  }

  /**
   * Reports which channels ICT has switched on, which of them are required, and why a request was
   * refused if one was.
   *
   * <p>Returns the realm default plus all configurable applications (enabled non-built-in clients)
   * with their own policies or inherited state.
   */
  @GET
  @Path("channels")
  @Produces(MediaType.APPLICATION_JSON)
  public Response channels(@Context HttpHeaders headers, @Context UriInfo uriInfo) {
    if (!isIct(headers, uriInfo)) {
      return unauthorized();
    }
    RealmModel realm = session.getContext().getRealm();
    Set<String> defaultEnabled = EdcChannelPolicy.enabled(realm);
    Set<String> defaultRequired = EdcChannelPolicy.required(realm);

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("attribute", EdcChannelPolicy.ATTRIBUTE);
    result.put("attributeRequired", EdcChannelPolicy.ATTRIBUTE_REQUIRED);
    result.put("telegramConfigured", EdcChannelDetector.isTelegramConfigured(session));

    // Realm-wide default
    Map<String, Object> defaultPolicy = new LinkedHashMap<>();
    List<Map<String, Object>> defaultRows = new java.util.ArrayList<>();
    for (String channel : EdcChannelPolicy.all()) {
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("channel", channel);
      row.put("enabled", defaultEnabled.contains(channel));
      row.put("required", defaultRequired.contains(channel));
      defaultRows.add(row);
    }
    defaultPolicy.put("channels", defaultRows);
    result.put("default", defaultPolicy);

    // Per-application policies
    List<Map<String, Object>> applications = new java.util.ArrayList<>();
    for (ClientModel client : EdcChannelPolicy.configurableClients(realm)) {
      Set<String> clientEnabled = EdcChannelPolicy.enabledFor(client, realm);
      Set<String> clientRequired = EdcChannelPolicy.requiredFor(client, realm);
      boolean inherited = !EdcChannelPolicy.hasOwnPolicy(client);

      Map<String, Object> app = new LinkedHashMap<>();
      app.put("clientId", client.getClientId());
      app.put("name", client.getName() != null && !client.getName().isBlank() ? client.getName() : client.getClientId());
      app.put("inherited", inherited);
      app.put("enabledAttribute", EdcChannelPolicy.ownEnabledAttribute(client));
      app.put("requiredAttribute", EdcChannelPolicy.ownRequiredAttribute(client));

      List<Map<String, Object>> appRows = new java.util.ArrayList<>();
      for (String channel : EdcChannelPolicy.all()) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("channel", channel);
        row.put("enabled", clientEnabled.contains(channel));
        row.put("required", clientRequired.contains(channel));
        appRows.add(row);
      }
      app.put("channels", appRows);

      // Last changed timestamp if the client has its own policy. The attribute name lives in
      // EdcChannelPolicy so this read and the write in setChannels() cannot drift onto two
      // spellings, which is how the column silently goes permanently blank.
      String updated = client.getAttribute(EdcChannelPolicy.ATTRIBUTE_UPDATED);
      app.put("lastChanged", updated != null && !updated.isBlank() ? updated : null);

      applications.add(app);
    }
    result.put("applications", applications);

    return Response.ok(result, MediaType.APPLICATION_JSON).build();
  }

  /**
   * Switches channels on or off, and marks any of them as required.
   *
   * <p>With no {@code client} parameter, updates the realm-wide default. With a {@code client}
   * parameter, updates that client's own policy (or clears it back to inherited when
   * {@code channels} is empty/absent).
   *
   * <p>Non-destructive by design: tokens and Telegram links are left alone, so re-enabling a channel
   * restores it for everyone instantly. Anything else would make a toggle into a mass delete of
   * people's second factors, and on this realm those writes are the ones that are hard to undo -
   * see the class comment.
   *
   * <p>The whole set is replaced, so the caller sends the complete list. A partial update would make
   * "turn Telegram off" mean something different depending on what was there before.
   *
   * @param client optional client id; absent means the realm default
   * @param channels query parameter, comma separated; empty with a client present clears the override
   * @param required query parameter, comma separated; absent leaves the stored list untouched
   */
  @POST
  @Path("channels")
  @Produces(MediaType.APPLICATION_JSON)
  public Response setChannels(@QueryParam("client") String clientId,
      @QueryParam("channels") String channels,
      @QueryParam("required") String required,
      @Context HttpHeaders headers, @Context UriInfo uriInfo) {
    if (!isIct(headers, uriInfo)) {
      return unauthorized();
    }
    RealmModel realm = session.getContext().getRealm();
    ClientModel client = null;
    boolean isDefault = clientId == null || clientId.isBlank();

    if (!isDefault) {
      client = realm.getClientByClientId(clientId);
      if (client == null) {
        return Response.status(Response.Status.NOT_FOUND)
            .entity(Map.of("error", "No such client", "clientId", clientId)).build();
      }
      if (!client.isEnabled()) {
        return Response.status(Response.Status.CONFLICT)
            .entity(Map.of("error", "Client is disabled", "clientId", clientId)).build();
      }
      if (EdcChannelPolicy.isBuiltInClientId(clientId)) {
        return Response.status(Response.Status.CONFLICT)
            .entity(Map.of("error", "That client's channels are never read",
                "error_description",
                "It is a Keycloak resource server or a machine-to-machine id, so no sign-in is ever "
                    + "resolved against it and a policy here would be stored and do nothing. "
                    + "account-console, by contrast, is configurable and is what governs the "
                    + "self-service MFA page.")).build();
      }
    }

    // For a client, empty channels means "clear the override, inherit from default"
    if (!isDefault && (channels == null || channels.isBlank())) {
      client.removeAttribute(EdcChannelPolicy.ATTRIBUTE);
      client.removeAttribute(EdcChannelPolicy.ATTRIBUTE_REQUIRED);
      client.removeAttribute(EdcChannelPolicy.ATTRIBUTE_UPDATED);
      log.infof("method=setChannels client=%s status=CLEARED message=Policy cleared, now inherits default",
          clientId);
      return Response.ok(Map.of("status", "cleared", "inherits", true,
          "required", String.join(",", EdcChannelPolicy.required(realm))), MediaType.APPLICATION_JSON)
          .build();
    }

    if (channels == null) {
      return Response.status(Response.Status.BAD_REQUEST)
          .entity(Map.of("error", "channels is required",
              "error_description",
              "Comma-separated, e.g. " + String.join(",", EdcChannelPolicy.all())))
          .build();
    }

    Set<String> requested = EdcChannelPolicy.parse(channels);
    // parse() deliberately treats an unrecognisable value as "all on", which is right for a stored
    // attribute and wrong for a request: here it would turn a typo into a silent reset of the realm
    // to everything on. So the refusal is made here, where the intent is explicit.
    if (requested.size() == EdcChannelPolicy.all().size() && !namesAllChannels(channels)) {
      return Response.status(Response.Status.BAD_REQUEST)
          .entity(Map.of("error", "No recognisable channel", "channels", channels)).build();
    }

    String value;
    try {
      value = EdcChannelPolicy.serialise(requested);
    } catch (IllegalArgumentException e) {
      log.warnf("method=setChannels client=%s channels=%s status=REJECTED message=%s",
          isDefault ? "default" : clientId, channels, e.getMessage());
      return Response.status(Response.Status.CONFLICT)
          .entity(Map.of("error", e.getMessage(),
              "error_description",
              "Turning off every channel would leave nobody able to obtain a code. Leave one "
                  + "enabled."))
          .build();
    }

    // A policy that is not empty but still satisfiable by nobody. Backup codes are issued by the
    // wizard itself, so `backupCode` on its own leaves the enrolment chooser with no rows at all -
    // every user who reached it would sit at a page saying every method has been switched off. The
    // refusal belongs here rather than at read time because it is a property of what was just
    // stored, and this is the only place that knows both halves of it.
    if (!EdcChannelPolicy.isSatisfiable(requested)) {
      log.warnf("method=setChannels client=%s channels=%s status=REJECTED "
          + "message=No channel a user could actually set up", isDefault ? "default" : clientId,
          value);
      return Response.status(Response.Status.CONFLICT)
          .entity(Map.of("error", "Nobody could set up a channel under this policy",
              "error_description",
              "Backup codes are issued automatically, so they do not count as something a user can "
                  + "choose. Leave Email, Telegram or the authenticator app switched on."))
          .build();
    }

    // A requirement behind a channel that is switched off is a realm whose population is told to
    // enrol into something they cannot be offered. Refused rather than silently dropped, because
    // silently dropping is how an admin would believe a requirement is in force when it is not.
    String requiredValue = null;
    if (required != null) {
      Set<String> wanted = namesIn(required);
      if (!namesIn(channels).containsAll(wanted)) {
        Set<String> notEnabled = new java.util.LinkedHashSet<>(wanted);
        notEnabled.removeAll(namesIn(channels));
        log.warnf("method=setChannels client=%s required=%s status=REJECTED message=required channel switched off",
            isDefault ? "default" : clientId, wanted);
        return Response.status(Response.Status.CONFLICT)
            .entity(Map.of("error", "A required channel cannot be switched off",
                "error_description", "Switch off the requirement first, or leave the channel on. "
                    + "Not switched off: " + String.join(",", notEnabled)))
            .build();
      }
      requiredValue = EdcChannelPolicy.serialiseRequired(wanted);
    }

    if (isDefault) {
      realm.setAttribute(EdcChannelPolicy.ATTRIBUTE, value);
      if (requiredValue != null) {
        realm.setAttribute(EdcChannelPolicy.ATTRIBUTE_REQUIRED, requiredValue);
      }
      log.infof("method=setChannels client=default channels=%s required=%s status=SUCCESS", value,
          requiredValue == null ? "(unchanged)" : requiredValue);
    } else {
      client.setAttribute(EdcChannelPolicy.ATTRIBUTE, value);
      if (requiredValue != null) {
        client.setAttribute(EdcChannelPolicy.ATTRIBUTE_REQUIRED, requiredValue);
      }
      client.setAttribute(EdcChannelPolicy.ATTRIBUTE_UPDATED, Instant.now().toString());
      log.infof("method=setChannels client=%s channels=%s required=%s status=SUCCESS", clientId, value,
          requiredValue == null ? "(unchanged)" : requiredValue);
    }

    Map<String, Object> body = new LinkedHashMap<>();
    body.put("status", "ok");
    body.put("channels", value);
    body.put("required", requiredValue == null
        ? String.join(",", isDefault ? EdcChannelPolicy.required(realm)
            : EdcChannelPolicy.requiredFor(client, realm))
        : requiredValue);
    return Response.ok(body, MediaType.APPLICATION_JSON).build();
  }

  /**
   * The channel names in a request parameter, ignoring anything unrecognisable.
   *
   * <p>Unlike {@link EdcChannelPolicy#parse} this does not substitute "everything" for nonsense: it
   * is used on the required list, where an unrecognisable word must narrow the request rather than
   * silently widen it.
   */
  private Set<String> namesIn(String commaSeparated) {
    Set<String> names = new java.util.LinkedHashSet<>();
    for (String part : commaSeparated.split(",")) {
      String name = part.trim();
      if (!name.isEmpty()) {
        String canonical = EdcChannelPolicy.canonical(name);
        if (canonical != null) {
          names.add(canonical);
        }
      }
    }
    return names;
  }

  /** Whether a request names every channel, as opposed to only unrecognised words. */
  private boolean namesAllChannels(String channels) {
    int named = 0;
    for (String part : channels.split(",")) {
      String name = part.trim();
      if (!name.isEmpty() && EdcChannelPolicy.canonical(name) != null) {
        named++;
      }
    }
    return named >= EdcChannelPolicy.all().size();
  }

  private Response unauthorized() {
    return Response.status(Response.Status.UNAUTHORIZED)
        .entity(Map.of("error", "Realm management credentials are required",
            "error_description",
            "The token must be issued by this realm and carry manage-realm. A master-realm "
                + "token will not do: a provider mounted here validates against this realm's keys, "
                + "and the master admin has no user record here to look up"))
        .build();
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
      return unauthorized();
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
   * <p>Two rules, and the second is the one that matters: the token must have been minted by
   * <em>this</em> realm, and its subject must be a user here holding realm-management authority.
   *
   * <p>An earlier version of this also accepted "the token was issued by a different realm", on the
   * reasoning that the master admin is a legitimate operator here. That branch is gone: a provider
   * mounted on this realm can only validate a token this realm minted, so it could never fire, and
   * code that looks like a privilege check but is not one is worse than no code - it invites a reader
   * to believe the master admin can reach this endpoint. It cannot.
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
      log.warn("method=isIct message=The bearer token did not authenticate against this realm");
      return false;
    }
    // The user the authenticator resolved the token to, rather than a second lookup by subject.
    // This is what AdminConsole.whoAmI does on the same token, so the two agree by construction -
    // and it is the only thing that works for a federated user, whose local record is what carries
    // the role mapping while the identity itself comes from LDAP.
    UserModel user = authResult.getUser();
    if (user == null) {
      log.warnf("method=isIct subject=%s message=Token subject has no user record in this realm",
          authResult.getToken().getSubject());
      return false;
    }
    if (holdsRealmManagement(session.getContext().getRealm(), user)) {
      return true;
    }
    if (hasManageRealm(authResult.getToken())) {
      log.infof("method=isIct user=%s message=Accepted from the token's role claims", user.getUsername());
      return true;
    }
    log.warnf("method=isIct user=%s message=No realm-management role on the user record",
        user.getUsername());
    return false;
  }

  /**
   * Whether the caller holds realm-management authority, read from the user record.
   *
   * <p>This is the admin API's own rule, and it is the only one that works. A realm-management role
   * is a <em>client</em> role of the {@code realm-management} client, and a token only ever carries
   * the roles of the client that asked for it: the stock {@code roles} client scope maps
   * {@code resource_access.${client_id}.roles}, and {@code ${client_id}} is the requesting client,
   * never {@code realm-management}. So {@code manage-realm} appears in a token at all only when some
   * client scope has been given a mapper that says so - and the admin console's does not.
   *
   * <p>Which means a gate that reads the token's claims rejects every admin-console session, i.e.
   * exactly the caller this endpoint exists for, while a gate that does not read them is blind to
   * composites and group-inherited roles. The user record is the authority in both cases: it is where
   * the roles were granted, and {@code hasRole} expands the composites and the group memberships the
   * way Keycloak's own admin permission checks do.
   *
   * <p>Both {@code admin} and {@code manage-realm} are accepted, since a realm admin is normally
   * granted the first, which is a composite holding the second.
   */
  private boolean holdsRealmManagement(RealmModel realm, UserModel user) {
    ClientModel realmManagement = realm.getClientByClientId(REALM_MANAGEMENT_CLIENT_ID);
    if (realmManagement == null) {
      log.warnf("method=holdsRealmManagement realm=%s message=No realm-management client", realm.getName());
      return false;
    }
    for (String roleName : REALM_ADMIN_ROLES) {
      RoleModel role = realmManagement.getRole(roleName);
      if (role != null && user.hasRole(role)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Whether the token carries realm-management authority in its claims.
   *
   * <p>A second opinion, not the rule: a deployment that has added a client scope mapping
   * realm-management roles into its tokens gets accepted here without any user lookup. Kept because
   * it is cheap and can only widen access for a token that this realm already vouches for - the
   * {@link #isIct} signature check has already run, so it cannot be what admits a master token.
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
