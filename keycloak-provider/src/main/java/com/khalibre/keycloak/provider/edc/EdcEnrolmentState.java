package com.khalibre.keycloak.provider.edc;

import java.time.Instant;
import java.time.format.DateTimeParseException;

import org.jboss.logging.Logger;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import com.khalibre.keycloak.provider.privacyIdea.PrivacyIdeaSettings;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;

/**
 * Whether a user has finished setting up their second step, and the record of it.
 *
 * <p>A user is enrolled once a channel works. That is deliberately derived from live state - a
 * privacyIDEA token or a linked Telegram account - rather than from a flag alone, so ICT clearing a
 * user's channels sends them back through enrolment without anyone having to remember to clear a
 * second thing. The attribute is still written on completion, because "did this person go through
 * it, and when" is exactly what ICT needs to answer from the user record without a privacyIDEA
 * query.
 *
 * <p>The completion marker is a user attribute written in-process, like the Telegram attributes. It
 * is not written through the admin REST API: this realm federates to LDAP with
 * {@code editMode=Writable}, and an unmapped attribute pushed through the admin API does not
 * survive.
 */
public final class EdcEnrolmentState {

  private static final Logger log = Logger.getLogger(EdcEnrolmentState.class);

  /** ISO-8601 instant of the moment enrolment finished. Its presence is what "enrolled" means. */
  public static final String ATTR_ENROLLED_AT = "edc-mfa-enrolled-at";

  /** Which channel the user finished on, so a support call does not need to look it up. */
  public static final String ATTR_ENROLLED_CHANNEL = "edc-mfa-enrolled-channel";

  /**
   * Set to {@code true} to exempt a user from enrolment entirely.
   *
   * <p>For the non-human accounts that share this realm. {@code ldap-svc} has no tokens and no
   * Telegram account, so it would be stopped at every sign-in by a wizard that cannot help it, and
   * nothing it does can ever get it past. Exempting it is a decision to be made deliberately rather
   * than discovered in production.
   */
  public static final String ATTR_EXEMPT = "edc-mfa-enrolment-exempt";

  /** How a user finished enrolment. Values match the channel names used everywhere else. */
  public static final String CHANNEL_TELEGRAM = "telegram";
  public static final String CHANNEL_TOTP = "totp";
  public static final String CHANNEL_EMAIL = "email";

  private EdcEnrolmentState() {
  }

  /**
   * Whether this user still has to be walked through setting a second step up.
   *
   * <p>Two ways out, both deliberate: the completion marker, or an explicit exemption. Without
   * either, anyone who cannot use any channel - which is most of this workforce, since most staff
   * have no email address on file - would be stuck at a screen they cannot get past.
   *
   * <p>A marker on its own is not enough: once ICT clears someone's channels, the channels are gone
   * but the marker is not, and the user has to do it again.
   */
  public static boolean requiresEnrolment(KeycloakSession session, PrivacyIdeaService privacyIdea,
      UserModel user) {
    if (user == null) {
      return false;
    }
    if (isExempt(user)) {
      return false;
    }
    if (!isComplete(user)) {
      return true;
    }
    return EdcChannelDetector.hasNoUsableChannel(
        EdcChannelDetector.detect(session, privacyIdea, user));
  }

  /** Whether the completion marker is present and readable. */
  public static boolean isComplete(UserModel user) {
    return enrolledAt(user) != null;
  }

  /** When enrolment finished, or {@code null} if it never has. */
  public static Instant enrolledAt(UserModel user) {
    String value = user == null ? null : user.getFirstAttribute(ATTR_ENROLLED_AT);
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Instant.parse(value.trim());
    } catch (DateTimeParseException e) {
      // A hand-edited or truncated value still means the person went through the wizard; only the
      // timestamp is lost. Refusing to treat it as enrolled would lock someone out over a typo.
      log.warnf("method=enrolledAt user=%s value=%s is not an ISO-8601 instant", user.getUsername(),
          value);
      return Instant.EPOCH;
    }
  }

  /** Whether this user is exempt from enrolment. */
  public static boolean isExempt(UserModel user) {
    if (user == null) {
      return false;
    }
    if (user.getServiceAccountClientLink() != null) {
      // Keycloak's own service accounts: no human is ever going to enrol them.
      return true;
    }
    return "true".equalsIgnoreCase(user.getFirstAttribute(ATTR_EXEMPT));
  }

  /**
   * Records that enrolment finished, and clears the required action that drove it.
   *
   * <p>Both halves matter. Leaving the required action in place would send the user round the
   * wizard again on their very next sign-in.
   */
  public static void markComplete(KeycloakSession session, UserModel user, String channel) {
    if (user == null) {
      return;
    }
    user.setSingleAttribute(ATTR_ENROLLED_AT, Instant.now().toString());
    if (channel != null && !channel.isBlank()) {
      user.setSingleAttribute(ATTR_ENROLLED_CHANNEL, channel.trim());
    }
    user.removeRequiredAction(EdcMfaEnrolmentRequiredAction.PROVIDER_ID);
    joinEnrolmentGroup(session, user);
    log.infof("method=markComplete user=%s channel=%s", user.getUsername(), channel);
  }

  /**
   * Adds the user to the realm's MFA group, which is the operator-facing record of who has set a
   * second step up.
   *
   * <p>Called from here rather than from each channel's own step because this is the one place all
   * three of them converge, so Telegram, an authenticator app and email cannot drift apart on who
   * counts as enrolled.
   *
   * <p>Group membership is the durable place to record this, unlike the marker attributes: it lives
   * in {@code USER_GROUP_MEMBERSHIP}, and with no LDAP group mapper attached nothing rewrites it on
   * sync. That is the opposite of the {@code edc-mfa-*} attributes, which an admin REST delete does
   * not survive.
   */
  public static void joinEnrolmentGroup(KeycloakSession session, UserModel user) {
    withEnrolmentGroup(session, user, "join", true);
  }

  /**
   * Removes the user from the MFA group.
   *
   * <p>Safe with this deployment's flow: the OTP gate is {@code edc-mfa-enrolled}, which reads an
   * auth note rather than the group, and no group-based gate exists anywhere in the realm. If a group
   * gate is ever added, this has to be revisited - taking a member out of it must not be what lets
   * someone past a second factor.
   */
  public static void leaveEnrolmentGroup(KeycloakSession session, UserModel user) {
    withEnrolmentGroup(session, user, "leave", false);
  }

  private static void withEnrolmentGroup(KeycloakSession session, UserModel user, String action,
      boolean join) {
    if (session == null || user == null) {
      return;
    }
    try {
      RealmModel realm = session.getContext().getRealm();
      String name = PrivacyIdeaSettings.resolve(session).enrolmentGroup();
      // RealmModel has no by-name lookup in KC 26; the provider's exact-match search is the way.
      GroupModel group = realm == null ? null
          : session.groups().searchForGroupByNameStream(realm, name, true, 0, 1).findFirst()
              .orElse(null);
      if (group == null) {
        // Not an error: enrolment must still complete and write its marker even where no group has
        // been created. Reported loudly because the operator will expect membership to appear.
        log.warnf("method=%sEnrolmentGroup user=%s reason=noSuchGroup "
            + "message=No group named %s in realm %s; enrolment still recorded on the user",
            action, user.getUsername(), name, realm == null ? "?" : realm.getName());
        return;
      }
      if (join) {
        if (!user.isMemberOf(group)) {
          user.joinGroup(group);
          log.infof("method=joinEnrolmentGroup user=%s group=%s", user.getUsername(), name);
        }
      } else {
        if (user.isMemberOf(group)) {
          user.leaveGroup(group);
          log.infof("method=leaveEnrolmentGroup user=%s group=%s", user.getUsername(), name);
        }
      }
    } catch (Exception e) {
      // Enrolment state is the thing that must not fail; the group is a mirror of it.
      log.warnf("method=%sEnrolmentGroup user=%s error=%s", action,
          user == null ? null : user.getUsername(), e.getMessage());
    }
  }

  /**
   * Forgets that enrolment ever finished.
   *
   * <p>What ICT calls when they clear someone's channels: the next sign-in walks them through
   * enrolment again from scratch.
   */
  public static void clear(KeycloakSession session, UserModel user) {
    if (user == null) {
      return;
    }
    user.removeAttribute(ATTR_ENROLLED_AT);
    user.removeAttribute(ATTR_ENROLLED_CHANNEL);
    leaveEnrolmentGroup(session, user);
    log.infof("method=clear user=%s", user.getUsername());
  }
}
