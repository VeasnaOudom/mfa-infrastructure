package com.khalibre.keycloak.provider.edc;

import com.khalibre.keycloak.provider.account.AccountConsoleCaller;
import com.khalibre.keycloak.provider.privacyIdea.PrivacyIdeaSettings;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import com.khalibre.keycloak.provider.telegram.bot.TelegramBotClient;
import com.khalibre.keycloak.provider.telegram.idp.TelegramIdentityProvider;
import com.khalibre.keycloak.provider.telegram.state.AuthState;
import com.khalibre.keycloak.provider.telegram.state.AuthStateCache;
import com.khalibre.keycloak.provider.telegram.state.AuthStateSession;
import com.khalibre.keycloak.provider.util.FederatedIdentity;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.events.Event;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.utils.StringUtil;

/**
 * Lets a user manage their own MFA channels from the account console.
 *
 * <p>Mounted at {@code /realms/{realm}/edc-mfa-settings/} by {@link EdcMfaSettingsResourceFactory}.
 *
 * <p>Every endpoint acts on the caller and nobody else. The user comes from a verified
 * account-client bearer token and is never read from a parameter, so this cannot be pointed at
 * another account the way an admin endpoint can.
 *
 * <p>Channel state is read through {@link EdcChannelDetector} rather than recomputed here, so this
 * page and the sign-in flow cannot disagree about what a user has. Writes go through
 * {@link PrivacyIdeaService}, which is the only thing in the project that talks to privacyIDEA.
 *
 * <p>Two things this deliberately does not do, both of which matter more than the convenience:
 * <ul>
 * <li>It does not require step-up authentication. Removing a channel or reissuing backup codes is
 * security-sensitive, and today anyone holding a console session can do both. The endpoints are
 * shaped so that a password re-check can be dropped in front of the write methods later without
 * changing the API.
 * <li>It does not stop a user removing their last channel. That is allowed on purpose - somebody
 * whose only channel is broken has to be able to get rid of it - and the consequence is that
 * {@link EdcEnrolmentState#requiresEnrolment} starts owing them the wizard at their next sign-in,
 * which the response reports so the console can warn them first.
 * </ul>
 */
public class EdcMfaSettingsResource implements org.keycloak.services.resource.RealmResourceProvider {

  private static final Logger log = Logger.getLogger(EdcMfaSettingsResource.class);

  /** Channel identifiers, matching the names used by {@link EdcEnrolmentState}. */
  public static final String CHANNEL_TELEGRAM = "telegram";
  public static final String CHANNEL_TOTP = "totp";
  public static final String CHANNEL_EMAIL = "email";
  public static final String CHANNEL_BACKUP_CODE = "backupCode";

  /** privacyIDEA token types behind each channel. */
  private static final String TYPE_SPASS = "spass";
  private static final String TYPE_TOTP = "totp";
  private static final String TYPE_HOTP = "hotp";
  private static final String TYPE_TAN = "tan";

  /**
   * Keys the in-progress enrolment under the user rather than under an authentication session.
   *
   * <p>The login flow keys its {@link AuthState} under the root authentication session, because a
   * browser that is mid-sign-in has one. An account console request has none: Keycloak only populates
   * an authentication session for login-action requests, so the session id there is null and
   * {@code singleUseObjects().get(null)} throws. The user id is available on every request here and
   * is just as unforgeable, since it is read from the verified token rather than the URL.
   */
  private static final String SCAN_KEY_PREFIX = "edc-mfa-settings:scan:";

  private final KeycloakSession session;
  private String callerSessionId;

  public EdcMfaSettingsResource(KeycloakSession session) {
    this.session = session;
  }

  // ------------------------------------------------------------------ read

  /**
   * Everything the page renders: which channels are on, when each was added, which could be added,
   * and what would happen if one were removed.
   *
   * <p>{@code removableAlone} is the one field with a real decision in it. It is true when turning
   * this channel off would leave the user with no way to get a code at all, which is legal but means
   * they meet the enrolment wizard at their next sign-in. The page says so before they do it.
   */
  @GET
  @Path("channels")
  @Produces(MediaType.APPLICATION_JSON)
  public Response channels(@Context UriInfo uriInfo, @Context HttpHeaders headers) {
    Caller caller = requireCaller(uriInfo, headers);
    UserModel user = caller.user();
    ClientModel client = caller.client();

    PrivacyIdeaService privacyIdea = privacyIdea();

    // A privacyIDEA outage must not take the whole page down, and it must not quietly report every
    // channel as "not set up" either - that reads as "my tokens have vanished" and invites the user to
    // re-enrol over the top of working ones. Detected still works best-effort; the flag below tells
    // the page to show the state as unknown instead of offering changes.
    String adminToken = null;
    boolean reachable = true;
    try {
      adminToken = adminToken(privacyIdea);
    } catch (Exception e) {
      reachable = false;
      log.errorf(e, "method=channels user=%s message=privacyIDEA unreachable", user.getUsername());
    }

    Map<String, String> detected =
        EdcChannelDetector.detect(session, privacyIdea, user, client);

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("telegram", telegramState(user, client, detected));
    result.put("totp", codeChannelState(CHANNEL_TOTP, TYPE_TOTP, user, client, adminToken,
        privacyIdea, detected));
    result.put("email", emailState(detected, user, client, adminToken, privacyIdea));
    result.put("backupCode", backupCodeState(user, client, adminToken, privacyIdea));
    result.put("available", reachable ? availableChannels(user, detected, client) : List.of());
    result.put("reachable", reachable);
    result.put("enrolmentRequired",
        EdcEnrolmentState.requiresEnrolment(session, privacyIdea, user, client));
    result.put("telegramConfigured", EdcChannelDetector.isTelegramConfigured(session));
    result.put("emailAddressOnFile", EdcChannelDetector.hasEmailAddress(user));
    return json(result);
  }

  private Map<String, Object> telegramState(UserModel user, ClientModel client,
      Map<String, String> detected) {
    Map<String, Object> state = new LinkedHashMap<>();
    boolean active = "1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM));
    state.put("active", active);
    if (active) {
      state.put("label", detected.get(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM_HANDLE));
    }
    state.put("configured", telegramLinked(user));
    state.put("switchedOff", switchedOff(CHANNEL_TELEGRAM, client));
    return state;
  }

  /**
   * An authenticator-app channel. No label: it is not tied to a device the server can describe.
   *
   * <p>{@code configured} is what separates "you have this set up" from "you have never set this
   * up".
   * {@code active} is the answer after the channel policy has been applied, so the two differ
   * exactly when ICT has switched the channel off for somebody who had it - which is the case the
   * page has to explain rather than hide, since a channel that silently vanishes reads as the
   * user's own setup having been deleted.
   */
  private Map<String, Object> codeChannelState(String channel, String type, UserModel user,
      ClientModel client, String adminToken, PrivacyIdeaService privacyIdea,
      Map<String, String> detected) {
    Map<String, Object> state = new LinkedHashMap<>();
    state.put("active", "1".equals(detected.get(noteFor(channel))));
    PrivacyIdeaService.TokenInfo token = firstToken(user, type, adminToken, privacyIdea);
    state.put("configured", token != null);
    state.put("switchedOff", switchedOff(channel, client));
    if (token != null && token.since() != null) {
      state.put("since", token.since().toString());
    }
    return state;
  }

  private Map<String, Object> emailState(Map<String, String> detected, UserModel user,
      ClientModel client, String adminToken, PrivacyIdeaService privacyIdea) {
    Map<String, Object> state = codeChannelState(CHANNEL_EMAIL, TYPE_SPASS, user, client,
        adminToken, privacyIdea, detected);
    if ("1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_EMAIL))) {
      state.put("label", detected.get(EdcMfaChannelsAuthenticator.NOTE_EMAIL_MASKED));
    }
    return state;
  }

  /**
   * Whether ICT has switched this channel off for the policy that applies here.
   *
   * <p>The client is threaded through rather than defaulted to null. Passing null answers with the
   * realm's policy, which is right for the sign-in flow and wrong here: the "switched off" badge on
   * this page has to agree with the add list next to it, and that list is already client-scoped.
   * Two halves of one screen answering from two different policies is how a user ends up looking at
   * a channel they cannot add and no explanation for it.
   */
  private boolean switchedOff(String channel, ClientModel client) {
    return !EdcChannelPolicy.isEnabled(client, session.getContext().getRealm(),
        policyNameFor(channel));
  }

  /**
   * The map from the page's channel names to the policy's.
   *
   * <p>Spelled out because the two sets do not share a spelling: the page says {@code backupCode}
   * where
   * the policy does too, but the settings resource has its own {@code CHANNEL_*} constants and
   * those are what arrive here.
   */
  private String policyNameFor(String channel) {
    return switch (channel) {
      case CHANNEL_TELEGRAM -> EdcChannelPolicy.TELEGRAM;
      case CHANNEL_TOTP -> EdcChannelPolicy.TOTP;
      case CHANNEL_EMAIL -> EdcChannelPolicy.EMAIL;
      case CHANNEL_BACKUP_CODE -> EdcChannelPolicy.BACKUP_CODE;
      default -> channel;
    };
  }

  /**
   * Whether this user has a Telegram chat linked, which outlives the SPASS token.
   */
  private boolean telegramLinked(UserModel user) {
    return EdcChannelDetector.telegramChatId(session, user) != null;
  }

  private Map<String, Object> backupCodeState(UserModel user, ClientModel client, String adminToken,
      PrivacyIdeaService privacyIdea) {
    Map<String, Object> state = new LinkedHashMap<>();
    PrivacyIdeaService.TokenInfo token = firstToken(user, TYPE_TAN, adminToken, privacyIdea);
    state.put("active", token != null);
    state.put("configured", token != null);
    state.put("switchedOff", switchedOff(CHANNEL_BACKUP_CODE, client));
    if (token != null) {
      if (token.since() != null) {
        state.put("since", token.since().toString());
      }
      // Only shown when privacyIDEA actually reports it. A missing count is not a count of zero: a
      // TAN token that has run out goes inactive by itself and would not be returned here at all.
      if (token.count() != null) {
        state.put("count", token.count());
      }
    }
    return state;
  }

  /** Channels the user could turn on right now, excluding the ones already on. */
  private List<String> availableChannels(UserModel user, Map<String, String> detected, ClientModel client) {
    java.util.ArrayList<String> available = new java.util.ArrayList<>();
    // A channel ICT has switched off is not offered here either. The detector has already withdrawn
    // it from `detected`, so a user holding one simply does not see it as switchable-on - but that is
    // the *remove* path. Without these checks the add list would still offer it, and start() would
    // happily create the token, which is a self-service bypass of the admin switch.
    RealmModel realm = session.getContext().getRealm();
    if (EdcChannelPolicy.isEnabled(client, realm, EdcChannelPolicy.TELEGRAM)
        && EdcChannelDetector.isTelegramConfigured(session)
        && !"1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM))) {
      available.add(CHANNEL_TELEGRAM);
    }
    if (EdcChannelPolicy.isEnabled(client, realm, CHANNEL_TOTP)
        && !"1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_TOTP))) {
      available.add(CHANNEL_TOTP);
    }
    // A SPASS token carries both Email and Telegram, so Email reads as on whenever one exists. It is
    // therefore not offered to someone who already has Telegram via that same token - there is
    // nothing to switch on, and offering it would produce a no-op button.
    if (EdcChannelPolicy.isEnabled(client, realm, CHANNEL_EMAIL)
        && EdcChannelDetector.hasEmailAddress(user)
        && !"1".equals(detected.get(EdcMfaChannelsAuthenticator.NOTE_EMAIL))) {
      available.add(CHANNEL_EMAIL);
    }
    return available;
  }

  // ---------------------------------------------------------------- remove

  /**
   * Turns one channel off.
   *
   * <p>Telegram removes the link, not a privacyIDEA token: Telegram and Email share one SPASS
   * token, so deleting it to turn Email off also takes away the only path the bot can send a code
   * down, and Telegram is withdrawn with it. The response names that, and the page confirms it
   * before calling.
   */
  @POST
  @Path("channels/{channel}/remove")
  @Produces(MediaType.APPLICATION_JSON)
  public Response remove(@PathParam("channel") String channel, @Context UriInfo uriInfo,
      @Context HttpHeaders headers) {
    Caller caller = requireCaller(uriInfo, headers);
    UserModel user = caller.user();
    RealmModel realm = session.getContext().getRealm();

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("channel", channel);

    try {
      switch (channel) {
        case CHANNEL_TELEGRAM -> {
          boolean removed = EdcTelegramLink.unlink(session, realm, user);
          result.put("removed", removed);
          if (removed) {
            emitChannelEvent(user, EventType.REMOVE_FEDERATED_IDENTITY, channel);
          }
        }
        case CHANNEL_TOTP -> {
          boolean removed = deleteTokens(user, List.of(TYPE_TOTP, TYPE_HOTP));
          result.put("removed", removed);
          if (removed) {
            emitChannelEvent(user, EventType.REMOVE_TOTP, channel);
          }
        }
        case CHANNEL_EMAIL -> {
          boolean removed = deleteTokens(user, List.of(TYPE_SPASS));
          result.put("removed", removed);
          if (removed) {
            emitChannelEvent(user, EventType.REMOVE_CREDENTIAL, channel);
          }
        }
        case CHANNEL_BACKUP_CODE -> {
          boolean removed = deleteTokens(user, List.of(TYPE_TAN));
          result.put("removed", removed);
          if (removed) {
            emitChannelEvent(user, EventType.REMOVE_CREDENTIAL, channel);
          }
        }
        default -> {
          return Response.status(Response.Status.BAD_REQUEST)
              .entity(Map.of("error", "Unknown channel")).build();
        }
      }
    } catch (Exception e) {
      log.errorf(e, "method=remove user=%s channel=%s", user.getUsername(), channel);
      return failure(e);
    }

    // Removing a channel is enrolment all over again only if it was the last one. Re-derived here
    // rather than guessed, because Email and Telegram share a token and removing one can take the
    // other with it.
    Map<String, String> after = EdcChannelDetector.detect(session, privacyIdea(), user, caller.client());
    boolean stranded = EdcChannelDetector.hasNoUsableChannel(after);
    result.put("willNeedEnrolment", stranded);
    if (stranded) {
      EdcEnrolmentState.clear(session, user);
      // Queued, not merely left: requiresEnrolment needs the marker to be absent, so clearing it is
      // what makes the wizard run next time. Taking the required action away as well would leave a
      // sign-in where neither the OTP gate nor the wizard does anything.
      user.addRequiredAction(EdcMfaEnrolmentRequiredAction.PROVIDER_ID);
    }

    log.infof("method=remove user=%s channel=%s stranded=%s", user.getUsername(), channel, stranded);
    return json(result);
  }

  // ----------------------------------------------------------------- start

  /**
   * Begins turning a channel on.
   *
   * <p>Returns whatever the next step needs: an {@code otpauth://} URI to draw as a QR, a masked
   * address and a code already sent, or a Telegram deeplink to scan.
   */
  @POST
  @Path("channels/{channel}/start")
  @Produces(MediaType.APPLICATION_JSON)
  public Response start(@PathParam("channel") String channel, @Context UriInfo uriInfo,
      @Context HttpHeaders headers) {
    Caller caller = requireCaller(uriInfo, headers);
    UserModel user = caller.user();
    ClientModel client = caller.client();

    try {
      // Server-side, not just hidden in the UI: the add list is a convenience, and this is the check
      // that makes the admin switch mean anything. Without it a user could post to a channel that
      // ICT switched off and enrol on it anyway.
      //
      // Client-scoped, because the switch can be per-application and this is the write that would
      // enact it. Checking the realm default here instead would leave the application's own
      // "switched off" enforced by nothing at all - the one path where a policy that looks in force
      // is not.
      if (!EdcChannelPolicy.isEnabled(client, session.getContext().getRealm(), channel)) {
        log.warnf("method=start user=%s channel=%s status=REJECTED "
            + "message=Channel is switched off for this policy", user.getUsername(), channel);
        return Response.status(Response.Status.FORBIDDEN)
            .entity(Map.of("error", "This channel is switched off", "channel", channel))
            .build();
      }
      return switch (channel) {
        case CHANNEL_TOTP -> startTotp(user);
        case CHANNEL_EMAIL -> startEmail(user, client);
        case CHANNEL_TELEGRAM -> startTelegramScan(user);
        default -> Response.status(Response.Status.BAD_REQUEST)
            .entity(Map.of("error", "Unknown channel")).build();
      };
    } catch (Exception e) {
      log.errorf(e, "method=start user=%s channel=%s", user.getUsername(), channel);
      return failure(e);
    }
  }

  private Response startTotp(UserModel user) throws Exception {
    PrivacyIdeaSettings.Settings settings = settings();
    PrivacyIdeaService privacyIdea = privacyIdea();
    String adminToken = adminToken(privacyIdea);

    // Delete before enrolling, or a user who replaces an authenticator app ends up with two and
    // cannot tell which one is signing them in.
    deleteTokens(user, List.of(TYPE_TOTP, TYPE_HOTP));
    PrivacyIdeaService.InitialisedToken token =
        privacyIdea.initToken(user.getUsername(), TYPE_TOTP, adminToken, settings.totpTokenParams());
    if (token.googleUrl() == null) {
      throw new IllegalStateException("privacyIDEA issued no enrolment URI");
    }

    return json(Map.of("channel", CHANNEL_TOTP, "enrolmentUri", token.googleUrl(),
        "codeLength", settings.backupCodeLength()));
  }

  private Response startEmail(UserModel user, ClientModel client) throws Exception {
    if (!EdcChannelDetector.hasEmailAddress(user)) {
      return Response.status(Response.Status.CONFLICT)
          .entity(Map.of("error", "No email address on file")).build();
    }
    PrivacyIdeaSettings.Settings settings = settings();
    PrivacyIdeaService privacyIdea = privacyIdea();
    String adminToken = adminToken(privacyIdea);

    List<PrivacyIdeaService.TokenInfo> existing = activeTokens(user, TYPE_SPASS, adminToken, privacyIdea);
    String serial = existing.isEmpty()
        ? privacyIdea.initToken(user.getUsername(), TYPE_SPASS, adminToken, Map.of()).serial()
        : existing.get(0).serial();

    // Proving the address works is the point: a code is sent, and the channel is only marked on once
    // the user has typed it back.
    EdcOtpDelivery.issue(session, session.getContext().getRealm(), client, user, settings,
        privacyIdea, adminToken, serial, clientIp());

    return json(Map.of("channel", CHANNEL_EMAIL,
        "label", EdcChannelDetector.maskEmail(user.getFirstAttribute("email")),
        "codeLength", settings.backupCodeLength(),
        "expiresInMinutes", settings.spassExpiryMinutes()));
  }

  /**
   * Mints a Telegram deeplink to scan.
   *
   * <p>Also makes sure a SPASS token exists. Telegram is not a channel on its own: the bot can only
   * send the PIN for a token that exists, so linking Telegram without one produces a link that looks
   * set up and can never deliver a code. This is the same trap that
   * {@link EdcChannelDetector#withdrawUndeliverableTelegram(Map)} fails closed on at sign-in.
   */
  private Response startTelegramScan(UserModel user) throws Exception {
    if (!EdcChannelDetector.isTelegramConfigured(session)) {
      return Response.status(Response.Status.SERVICE_UNAVAILABLE)
          .entity(Map.of("error", "Telegram is not available on this deployment")).build();
    }
    IdentityProviderModel idp =
        session.identityProviders().getByAlias(EdcChannelDetector.TELEGRAM_IDP_ALIAS);
    OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig(idp);
    String botToken = config.getClientSecret();
    String botUsername = config.getClientId();

    PrivacyIdeaService privacyIdea = privacyIdea();
    String adminToken = adminToken(privacyIdea);
    if (activeTokens(user, TYPE_SPASS, adminToken, privacyIdea).isEmpty()) {
      privacyIdea.initToken(user.getUsername(), TYPE_SPASS, adminToken, Map.of());
    }

    AuthStateSession.remove(scanKey(user));
    AuthState state = AuthStateSession.create(scanKey(user));
    String deepLink = "https://t.me/" + botUsername + "?start=login_" + state.getId();

    log.infof("method=startTelegramScan user=%s scanKey=%s stateId=%s",
        user.getUsername(), scanKey(user), state.getId());
    String requirePhoneMatch = user.getFirstAttribute(TelegramIdentityProvider.ATTR_TG_REQUIRE_PHONE_MATCH);
    boolean phoneMatchRequired = !StringUtil.isBlank(requirePhoneMatch) && requirePhoneMatch.equalsIgnoreCase("true");
    return json(Map.of("channel", CHANNEL_TELEGRAM, "deepLink", deepLink,
        "botUsername", botUsername, "requirePhoneMatch", phoneMatchRequired));
  }

  // ---------------------------------------------------------------- verify

  /** Completes a channel that was started earlier. */
  @POST
  @Path("channels/{channel}/verify")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response verify(@PathParam("channel") String channel, Map<String, String> body,
      @Context UriInfo uriInfo, @Context HttpHeaders headers) {
    UserModel user = requireCaller(uriInfo, headers).user();
    RealmModel realm = session.getContext().getRealm();

    try {
      if (CHANNEL_TELEGRAM.equals(channel)) {
        return verifyTelegram(user, realm);
      }

      String code = body == null ? null : body.get("code");
      if (code == null || code.isBlank()) {
        return Response.status(Response.Status.BAD_REQUEST)
            .entity(Map.of("error", "code is required")).build();
      }
      PrivacyIdeaService privacyIdea = privacyIdea();
      // No serial, on purpose: privacyIDEA tries every token the user holds, which is the same call
      // sign-in makes, so a channel behaves identically here and afterwards.
      if (!privacyIdea.validateCheck(user.getUsername(), code, adminToken(privacyIdea))) {
        return Response.status(Response.Status.UNAUTHORIZED)
            .entity(Map.of("error", "That code was not accepted")).build();
      }

      EdcEnrolmentState.markComplete(session, user, channel);
      emitChannelEvent(user, addEventTypeFor(channel), channel);
      return json(Map.of("status", "ok", "channel", channel));
    } catch (Exception e) {
      log.errorf(e, "method=verify user=%s channel=%s", user.getUsername(), channel);
      return failure(e);
    }
  }

  private Response verifyTelegram(UserModel user, RealmModel realm) {
    AuthState state = AuthStateSession.get(scanKey(user));
    if (state == null) {
      log.infof("method=verifyTelegram user=%s scanKey=%s message=NoStoredState",
          user.getUsername(), scanKey(user));
      return uncached(Response.Status.NOT_FOUND.getStatusCode(),
          Map.of("error", "No Telegram scan in progress"));
    }
    log.infof("method=verifyTelegram user=%s scanKey=%s stateId=%s status=%s chat=%s",
        user.getUsername(), scanKey(user), state.getId(), state.getStatus(),
        state.getTelegramUserId());
    EdcTelegramLink.Outcome outcome = EdcTelegramLink.apply(session, realm, user, state);
    if (outcome != EdcTelegramLink.Outcome.LINKED) {
      if (outcome == EdcTelegramLink.Outcome.EXPIRED) {
        AuthStateSession.remove(scanKey(user));
      }
      return uncached(EdcTelegramLink.statusOf(outcome), EdcTelegramLink.problem(outcome));
    }
    AuthStateSession.remove(scanKey(user));
    EdcEnrolmentState.markComplete(session, user, CHANNEL_TELEGRAM);
    emitChannelEvent(user, EventType.FEDERATED_IDENTITY_LINK, CHANNEL_TELEGRAM);
    return json(Map.of("status", "ok", "channel", CHANNEL_TELEGRAM));
  }

  // ------------------------------------------------------------------ poll

  /**
   * Where a Telegram scan has got to, for the account console to poll while the user is on their
   * phone.
   *
   * <p>Mirrors the login flow's {@code /telegram-auth/status}, including asking the bot for a phone
   * number once the account is seen not to be linked to anyone. That prompt is the step which turns
   * a Telegram account into a usable one, so skipping it here would leave the scan permanently
   * unfinished.
   */
  @GET
  @Path("channels/telegram/scan")
  @Produces(MediaType.APPLICATION_JSON)
  public Response telegramScan(@Context UriInfo uriInfo, @Context HttpHeaders headers) {
    UserModel user = requireCaller(uriInfo, headers).user();
    RealmModel realm = session.getContext().getRealm();

    AuthState state = AuthStateSession.get(scanKey(user));
    if (state == null) {
      // Distinguishable from an expiry on purpose: "never started" and "expired" used to answer
      // identically, so a page that had written the state and could not read it back was reported
      // to the user as "that QR code expired", which sends them round the loop for the wrong reason.
      log.infof("method=telegramScan user=%s scanKey=%s message=NoStoredState",
          user.getUsername(), scanKey(user));
      return uncached(Response.Status.NOT_FOUND.getStatusCode(),
          Map.of("status", "NO_SCAN", "error", "No scan is in progress for this account"));
    }
    if (state.isExpired()) {
      AuthStateSession.remove(scanKey(user));
log.infof("method=telegramScan user=%s scanKey=%s stateId=%s message=Expired",
          user.getUsername(), scanKey(user), state.getId());
      return uncached(Response.Status.GONE.getStatusCode(),
          Map.of("status", "EXPIRED", "error", "That Telegram code has expired"));
    }
    log.infof("method=telegramScan user=%s scanKey=%s stateId=%s status=%s chat=%s",
        user.getUsername(), scanKey(user), state.getId(), state.getStatus(),
        state.getTelegramUserId());

    boolean linkedToSomeoneElse = state.getTelegramUserId() != null
        && FederatedIdentity.isTelegramLinked(session,
            EdcChannelDetector.TELEGRAM_IDP_ALIAS, state.getTelegramUserId());
    if (!linkedToSomeoneElse && !state.isPhoneNumberRequested()) {
      askBotForPhoneNumber(user, state);
    }

    return json(Map.of("status", state.getStatus(), "scanned", state.getTelegramUserId() != null,
        "phoneRequested", state.isPhoneNumberRequested()));
  }

  private void askBotForPhoneNumber(UserModel user, AuthState state) {
    if (state.getTelegramUserId() == null) {
      // The bot has not seen /start yet, so there is nobody to prompt. Answering "not yet" is what
      // the page needs to keep polling rather than give up.
      return;
    }
    try {
      IdentityProviderModel idp =
          session.identityProviders().getByAlias(EdcChannelDetector.TELEGRAM_IDP_ALIAS);
      new TelegramBotClient(new OAuth2IdentityProviderConfig(idp).getClientSecret())
          .requestPhoneNumber(state.getTelegramUserId(), "Share your phone number so we can "
              + "finish linking your account.", "Share phone number");
      state.setPhoneNumberRequested(true);
      AuthStateCache.store(state.getId(), state);
    } catch (Exception e) {
      log.warnf("method=askBotForPhoneNumber user=%s error=%s", user.getUsername(), e.getMessage());
    }
  }

  // --------------------------------------------------------------- backup codes

  /**
   * Issues a fresh set of backup codes, replacing whatever the user had.
   *
   * <p>Delete first, then create. privacyIDEA stores a TAN token's codes hashed and will happily hold
   * two of them, so creating before deleting would leave the old set working - the one outcome that
   * makes "generate a new set" a security illusion.
   *
   * <p>The codes come back in this response and nowhere else, ever. They cannot be read again,
   * because privacyIDEA has only the hashes.
   */
  @POST
  @Path("channels/backupCode/regenerate")
  @Produces(MediaType.APPLICATION_JSON)
  public Response regenerateBackupCodes(@Context UriInfo uriInfo, @Context HttpHeaders headers) {
    UserModel user = requireCaller(uriInfo, headers).user();
    try {
      PrivacyIdeaSettings.Settings settings = settings();
      PrivacyIdeaService privacyIdea = privacyIdea();
      String adminToken = adminToken(privacyIdea);

      deleteTokens(user, List.of(TYPE_TAN));
      PrivacyIdeaService.InitialisedToken token =
          privacyIdea.initToken(user.getUsername(), TYPE_TAN, adminToken,
              settings.backupCodeTokenParams());
      if (token.otps().isEmpty()) {
        throw new IllegalStateException(
            "privacyIDEA issued no backup codes for " + user.getUsername());
      }
      EdcEnrolmentState.markComplete(session, user, CHANNEL_BACKUP_CODE);
      emitChannelEvent(user, EventType.UPDATE_CREDENTIAL, CHANNEL_BACKUP_CODE);
      return json(Map.of("codes", token.otps(), "count", token.otps().size()));
    } catch (Exception e) {
      log.errorf(e, "method=regenerateBackupCodes user=%s", user.getUsername());
      return failure(e);
    }
  }

  // ----------------------------------------------------------------- utils

  /**
   * The response for a request that blew up.
   *
   * <p>Deliberately does not say "could not reach privacyIDEA": that was here before, and it is a
   * guess. It made an unrelated NullPointerException read as a privacyIDEA outage, so the user was
   * told to try again in a moment for a fault that had nothing to do with either. The reason goes
   * in the body instead, because the console is the operator's own screen and "unexpected failure:
   * &lt;cause&gt;" is more use than a confident wrong answer.
   */
  private static Response failure(Exception e) {
    String reason = e.getMessage() == null || e.getMessage().isBlank()
        ? e.getClass().getSimpleName()
        : e.getMessage();
    return Response.status(Response.Status.BAD_GATEWAY)
        .entity(Map.of("error", "Could not complete that request", "reason", reason))
        .build();
  }

  /**
   * JSON response carrying an explicit {@code Cache-Control: no-store}.
   *
   * <p>Every response from this provider goes through here, and the reason is not tidiness. RFC 7234
   * §4.2.2 lists 410 as heuristically cacheable, and this provider answers 410 "that scan expired"
   * from a GET. With no cache header the browser stored that 410 and then replayed it on every
   * subsequent poll without ever asking the server again - so the account console reported a dead QR
   * forever while a freshly started scan sat on the server waiting for someone to read it. The QR
   * still worked, because the bot learned about the scan by long poll and never consulted the
   * browser. Add {@code no-store} to the polling endpoint and this class of bug cannot recur on any
   * other one.
   */
  private static Response json(Object entity) {
    return Response.ok(entity, MediaType.APPLICATION_JSON)
        .header("Cache-Control", "no-store")
        .build();
  }

  /**
   * A refusal that must never be cached, for the same reason as {@link #json}.
   *
   * <p>Caller supplies the status because the ones this endpoint returns - 404 for "no scan in
   * progress" and 410 for "expired" - are both heuristically cacheable.
   */
  private static Response uncached(int status, Object entity) {
    return Response.status(status)
        .entity(entity)
        .header("Cache-Control", "no-store")
        .build();
  }

  /**
   * The authenticated caller, and the client whose channel policy applies to them.
   *
   * <p>Resolved once per request and passed to everything that needs it. The two halves answer
   * different questions and have to come from the same token: the user is who they are, and the
   * client is whose policy governs which channels they may use. Reading them separately meant this
   * class authenticated the bearer token twice per request and then - worse - used the realm's
   * policy on one path and the client's on another.
   */
  private record Caller(UserModel user, ClientModel client) {

  }

  private Caller caller(UriInfo uriInfo, HttpHeaders headers) {
    AccountConsoleCaller.Caller resolved =
        AccountConsoleCaller.resolveCaller(session, uriInfo, headers);
    return resolved == null ? null : new Caller(resolved.user(), policyClient(resolved.token()));
  }

  /**
   * The caller, or a 401.
   *
   * <p>Every endpoint here acts on the caller and nobody else, so there is no path that can do
   * anything useful without them - a null check at each call site was one line each and three times
   * over, and it is exactly the kind of thing that gets dropped when a fourth endpoint is added.
   */
  private Caller requireCaller(UriInfo uriInfo, HttpHeaders headers) {
    Caller caller = caller(uriInfo, headers);
    if (caller == null) {
      throw new NotAuthorizedException("Bearer token required");
    }
    return caller;
  }

  /**
   * The client this token was issued for, which is the one whose policy applies.
   *
   * <p>{@code azp}, not the audience: the audience is {@code account}, which every console session
   * shares and which names no policy. {@code azp} names the client the token was actually requested
   * for.
   *
   * <p>On the stock account console this resolves to {@code account-console}, which is a Keycloak
   * built-in and therefore cannot carry a policy of its own - so today it always reads the realm
   * default. It is resolved rather than hard-coded so that a console reached through any other
   * client is governed by that client's policy instead, and so the answer and the check on
   * {@code start()} can never come from different places.
   */
  private ClientModel policyClient(org.keycloak.representations.AccessToken token) {
    if (token == null) {
      return null;
    }
    String clientId = token.getIssuedFor();
    if (clientId == null || clientId.isBlank()) {
      return null;
    }
    try {
      return session.getContext().getRealm().getClientByClientId(clientId);
    } catch (Exception e) {
      log.warnf("method=policyClient client=%s error=%s", clientId, e.getMessage());
      return null;
    }
  }

  private PrivacyIdeaSettings.Settings settings() {
    return PrivacyIdeaSettings.resolve(session);
  }

  private PrivacyIdeaService privacyIdea() {
    PrivacyIdeaSettings.Settings settings = settings();
    return new PrivacyIdeaService(settings.baseUrlTrimmed(), settings.adminUsername(),
        settings.adminPassword());
  }

  private static String adminToken(PrivacyIdeaService privacyIdea) throws Exception {
    String adminToken = privacyIdea.getPrivacyIdeaAuthToken();
    if (adminToken == null || adminToken.isBlank()) {
      throw new IllegalStateException("privacyIDEA refused the service account login");
    }
    return adminToken;
  }

  private EventType addEventTypeFor(String channel) {
    return switch (channel) {
      case CHANNEL_TOTP -> EventType.UPDATE_TOTP;
      case CHANNEL_EMAIL -> EventType.UPDATE_EMAIL;
      case CHANNEL_BACKUP_CODE -> EventType.UPDATE_CREDENTIAL;
      case CHANNEL_TELEGRAM -> EventType.FEDERATED_IDENTITY_LINK;
      default -> EventType.UPDATE_PROFILE;
    };
  }

  private void emitChannelEvent(UserModel user, EventType type, String channel) {
    EventStoreProvider store = session.getProvider(EventStoreProvider.class);
    if (store == null) {
      return;
    }

    Event event = new Event();
    event.setType(type);
    event.setRealmId(session.getContext().getRealm().getId());
    event.setUserId(user.getId());
    event.setIpAddress(clientIp());
    event.setTime(System.currentTimeMillis());
    if (callerSessionId != null && !callerSessionId.isBlank()) {
      event.setSessionId(callerSessionId);
    }
    if (session.getContext().getClient() != null) {
      event.setClientId(session.getContext().getClient().getClientId());
    }
    event.setDetails(Map.of(
        "auth_method", "account_console",
        "mfa_channel", channel));
    store.onEvent(event);
  }

  private boolean deleteTokens(UserModel user, List<String> types) throws Exception {
    PrivacyIdeaService privacyIdea = privacyIdea();
    String adminToken = adminToken(privacyIdea);
    int deleted = 0;
    for (String type : types) {
      for (PrivacyIdeaService.TokenInfo token : activeTokens(user, type, adminToken, privacyIdea)) {
        privacyIdea.deleteToken(token.serial(), adminToken);
        deleted++;
      }
    }
    return deleted > 0;
  }

  private List<PrivacyIdeaService.TokenInfo> activeTokens(UserModel user, String type,
      String adminToken, PrivacyIdeaService privacyIdea) {
    if (adminToken == null) {
      return List.of();
    }
    try {
      return privacyIdea.getActiveTokens(user.getUsername(), type, adminToken);
    } catch (Exception e) {
      log.warnf("method=activeTokens user=%s type=%s error=%s", user.getUsername(), type,
          e.getMessage());
      return List.of();
    }
  }

  private PrivacyIdeaService.TokenInfo firstToken(UserModel user, String type, String adminToken,
      PrivacyIdeaService privacyIdea) {
    List<PrivacyIdeaService.TokenInfo> tokens = activeTokens(user, type, adminToken, privacyIdea);
    return tokens.isEmpty() ? null : tokens.get(0);
  }

  private static String noteFor(String channel) {
    return switch (channel) {
      case CHANNEL_TOTP -> EdcMfaChannelsAuthenticator.NOTE_TOTP;
      case CHANNEL_EMAIL -> EdcMfaChannelsAuthenticator.NOTE_EMAIL;
      case CHANNEL_TELEGRAM -> EdcMfaChannelsAuthenticator.NOTE_TELEGRAM;
      default -> EdcMfaChannelsAuthenticator.NOTE_BACKUP_CODE;
    };
  }

  private String clientIp() {
    return session.getContext().getConnection() == null
        ? null
        : session.getContext().getConnection().getRemoteAddr();
  }

  private String scanKey(UserModel user) {
    return SCAN_KEY_PREFIX + user.getId();
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {
    // Nothing to release: every request builds its own privacyIDEA client.
  }
}