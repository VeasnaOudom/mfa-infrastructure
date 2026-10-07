package com.khalibre.keycloak.provider.edc;

import java.util.Map;

import org.jboss.logging.Logger;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.khalibre.keycloak.provider.telegram.bot.TelegramNotifier;
import com.khalibre.keycloak.provider.telegram.state.AuthState;

/**
 * Writes a completed Telegram scan onto a Keycloak user.
 *
 * <p>Single implementation of the rule that one Telegram account belongs to one Keycloak account.
 * The enrolment wizard reaches it through the {@code privacyidea} provider and the account console
 * through the {@code edc-mfa-settings} provider; both must enforce it identically, because getting it
 * wrong means two people's codes arriving at one phone.
 */
public final class EdcTelegramLink {

  private static final Logger log = Logger.getLogger(EdcTelegramLink.class);

  private EdcTelegramLink() {
  }

  /** Outcome of a link attempt, so a caller can turn it into the right status code and message. */
  public enum Outcome {
    /** The chat was written onto the user. */
    LINKED,
    /** No completed scan to apply. */
    NO_SCAN,
    /** The scan expired before it was applied. */
    EXPIRED,
    /** The scan has not finished yet; the caller should keep polling. */
    PENDING,
    /** Another Keycloak account already claims this Telegram chat. */
    ALREADY_LINKED,
    /** The scan carried no chat id at all. */
    NO_CHAT_ID
  }

  /**
   * Applies a finished scan to {@code user}, in process.
   *
   * <p>Both the federated identity and the four {@code telegram-*} attributes are written here
   * deliberately rather than left to the admin API: on this realm the user is LDAP-federated with
   * {@code editMode=Writable}, and an attribute pushed through the admin REST API is discarded
   * because it is not mapped in the directory. Only an in-process write survives.
   *
   * @param state the scan to apply, which the caller has already checked belongs to this user
   * @return what happened, so the caller can report it rather than assuming success
   */
  public static Outcome apply(KeycloakSession session, RealmModel realm, UserModel user,
      AuthState state) {
    // Order matters, and it is expiry first, then progress, then the chat id.
    //
    // A scan that has not happened yet has a null telegram user id - that is the state every link
    // spends most of its life in. Testing for it first reported "no chat id", which the account
    // console reads as a fatal error and stopped polling on, so the link could never complete. The
    // progress test below is what "not yet" means, and it has to come first for exactly that reason.
    if (state == null) {
      return Outcome.NO_SCAN;
    }
    if (state.isExpired()) {
      return Outcome.EXPIRED;
    }
    if (!"COMPLETED".equals(state.getStatus())) {
      return Outcome.PENDING;
    }
    // Only now, with the scan reported finished, is a missing chat id a real inconsistency.
    if (state.getTelegramUserId() == null) {
      return Outcome.NO_CHAT_ID;
    }

    String alias = EdcChannelDetector.TELEGRAM_IDP_ALIAS;
    String chatId = state.getTelegramUserId();

    UserModel owner = session.users().getUserByFederatedIdentity(realm,
        new FederatedIdentityModel(alias, chatId, null));
    if (owner == null) {
      owner = EdcChannelDetector.anotherUserHolding(session, realm, user, chatId);
    }
    if (owner != null && !owner.getId().equals(user.getId())) {
      log.warnf("method=apply user=%s chat=%s alsoHeldBy=%s message=TelegramAlreadyLinked",
          user.getUsername(), chatId, owner.getUsername());
      return Outcome.ALREADY_LINKED;
    }

    if (session.users().getFederatedIdentity(realm, user, alias) == null) {
      session.users().addFederatedIdentity(realm, user,
          new FederatedIdentityModel(alias, chatId, state.getUsername()));
    } else {
      session.users().updateFederatedIdentity(realm, user,
          new FederatedIdentityModel(alias, chatId, state.getUsername()));
    }

    user.setSingleAttribute(EdcChannelDetector.TELEGRAM_USER_ID_ATTR, chatId);
    user.setSingleAttribute(EdcChannelDetector.TELEGRAM_USERNAME_ATTR, state.getUsername());
    user.setSingleAttribute(EdcChannelDetector.TELEGRAM_FIRST_NAME_ATTR, state.getFirstName());
    user.setSingleAttribute(EdcChannelDetector.TELEGRAM_LAST_NAME_ATTR, state.getLastName());

    // Tell them it worked, from here rather than from each caller, so the enrolment wizard and the
    // account console both confirm and neither can quietly stop doing it. The phone is the only
    // place the person can act on the result: the page they came from closes on success and shows
    // nothing more, and a link made against the wrong Keycloak account is not obvious from the
    // Telegram side at all - which is exactly how extuser ended up holding someone else's chat.
    TelegramNotifier.send(session, chatId, "telegram.link-success");

    log.infof("method=apply status=SUCCESS username=%s", user.getUsername());
    return Outcome.LINKED;
  }

  /**
   * Removes every trace of a Telegram link from a user.
   *
   * <p>Both signals are cleared, not just the attribute: the detector prefers the attribute and falls
   * back to the federated identity, so clearing only one leaves a channel that still looks live.
   *
   * <p>In process, for the same reason {@link #apply} writes in process - this is the only kind of
   * write that survives on an LDAP-federated user.
   *
   * @return whether anything was actually removed
   */
  public static boolean unlink(KeycloakSession session, RealmModel realm, UserModel user) {
    boolean removed = false;
    for (String attribute : new String[] {
        EdcChannelDetector.TELEGRAM_USER_ID_ATTR,
        EdcChannelDetector.TELEGRAM_USERNAME_ATTR,
        EdcChannelDetector.TELEGRAM_FIRST_NAME_ATTR,
        EdcChannelDetector.TELEGRAM_LAST_NAME_ATTR}) {
      if (user.getFirstAttribute(attribute) != null) {
        user.removeAttribute(attribute);
        removed = true;
      }
    }
    try {
      if (session.users().getFederatedIdentity(realm, user,
          EdcChannelDetector.TELEGRAM_IDP_ALIAS) != null) {
        session.users().removeFederatedIdentity(realm, user,
            EdcChannelDetector.TELEGRAM_IDP_ALIAS);
        removed = true;
      }
    } catch (Exception e) {
      // Not fatal: the detector falls back to the attributes, and those are already gone.
      log.warnf("method=unlink user=%s error=%s", user.getUsername(), e.getMessage());
    }
    if (removed) {
      log.infof("method=unlink status=SUCCESS username=%s", user.getUsername());
    }
    return removed;
  }

  /**
   * A JSON body for an {@link Outcome} that is not a success.
   *
   * <p>Carries a machine-readable {@code code} alongside the message. Two of these outcomes are both
   * HTTP 409, and a caller has to tell them apart to know whether to keep waiting: {@code PENDING} is
   * the normal "not yet" and a retry is the right response, while {@code ALREADY_LINKED} is final and
   * retrying just spins until the scan ages out.
   */
  public static Map<String, Object> problem(Outcome outcome) {
    return switch (outcome) {
      case NO_SCAN -> Map.of("code", "NO_SCAN", "error", "No Telegram scan in progress");
      case EXPIRED -> Map.of("code", "EXPIRED", "error", "Telegram code expired");
      case PENDING -> Map.of("code", "PENDING", "error", "Telegram scan not finished yet");
      case ALREADY_LINKED -> Map.of("code", "ALREADY_LINKED",
          "error", "That Telegram account is already linked to another user");
      case NO_CHAT_ID -> Map.of("code", "NO_CHAT_ID", "error", "The scan carried no Telegram account");
      case LINKED -> Map.of("code", "LINKED", "status", "ok");
    };
  }

  /** HTTP status that goes with an {@link Outcome}. */
  public static int statusOf(Outcome outcome) {
    return switch (outcome) {
      case LINKED -> 200;
      case NO_SCAN, NO_CHAT_ID -> 404;
      case EXPIRED -> 410;
      case PENDING -> 409;
      case ALREADY_LINKED -> 409;
    };
  }
}