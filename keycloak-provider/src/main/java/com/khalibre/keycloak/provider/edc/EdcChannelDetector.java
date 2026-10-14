package com.khalibre.keycloak.provider.edc;

import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import com.khalibre.keycloak.provider.util.FederatedIdentity;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.ClientModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Works out which MFA channels a user can actually receive a code on: an active privacyIDEA SPASS
 * token enables Email, an active HOTP/TOTP token enables the authenticator app, and a linked
 * Telegram account enables Telegram.
 * <p>
 * Shared by the authenticator (which writes the result into authentication-session notes) and the
 * channels endpoint, so the page and the flow can never disagree.
 * <p>
 * Every lookup is best-effort: a privacyIDEA outage must not block sign-in, so failures degrade to
 * "channel unavailable".
 */
public final class EdcChannelDetector {

  private static final Logger log = Logger.getLogger(EdcChannelDetector.class);

  /**
   * Keycloak user attributes written when a Telegram account is linked.
   */
  public static final String TELEGRAM_USER_ID_ATTR = "telegram-user-id";
  public static final String TELEGRAM_USERNAME_ATTR = "telegram-username";
  public static final String TELEGRAM_FIRST_NAME_ATTR = "telegram-first-name";
  public static final String TELEGRAM_LAST_NAME_ATTR = "telegram-last-name";

  /**
   * Alias of the Telegram identity provider whose links make the channel available.
   */
  public static final String TELEGRAM_IDP_ALIAS = "telegram";

  /**
   * PrivacyIDEA holds an active {@code spass} token for this user.
   *
   * <p>The signal that something can actually deliver a code. Both Telegram and email are carried by
   * a {@code spass} token, which is what enrolment creates and what the sender writes the PIN to.
   */
  private static final String KEY_SPASS_TOKEN = "edc_spass_token";

  /**
   * Shape of a Telegram bot token: the bot's numeric id, a colon, then 35 base64url characters.
   * Cheaper and more reliable than asking Telegram whether the bot exists, and it cannot be fooled
   * by a masked or placeholder value, which is how an unconfigured realm usually looks.
   */
  static final Pattern BOT_TOKEN_PATTERN =
    Pattern.compile("^\\d{5,}:[A-Za-z0-9_-]{35}$");

  private EdcChannelDetector() {
  }

  /**
   * Whether a value has the shape of a Telegram bot token. Null-safe.
   */
  static boolean looksLikeBotToken(String token) {
    return token != null && BOT_TOKEN_PATTERN.matcher(token).matches();
  }

  /**
   * @return channel flags keyed by the note names the template and endpoint exchange
   */
  public static Map<String, String> detect(KeycloakSession session, PrivacyIdeaService privacyIdea,
      UserModel user) {
    return detect(session, privacyIdea, user, null);
  }

  /**
   * Client-aware overload: the channel policy is resolved from the client's own attributes where
   * present, falling back to the realm's.
   */
  public static Map<String, String> detect(KeycloakSession session, PrivacyIdeaService privacyIdea,
      UserModel user, ClientModel client) {
    Map<String, String> channels = new LinkedHashMap<>();
    channels.put(EdcMfaChannelsAuthenticator.NOTE_EMAIL, "0");
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TOTP, "0");
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM, "0");
    channels.put(EdcMfaChannelsAuthenticator.NOTE_BACKUP_CODE, "0");
    channels.put(KEY_SPASS_TOKEN, "0");
    channels.put(EdcMfaChannelsAuthenticator.NOTE_MASKED, "0");

    if (user == null) {
      return channels;
    }
    detectTelegram(session, user, channels);
    detectPrivacyIdeaTokens(privacyIdea, user, channels);
    suppressUndeliverableTelegram(user, channels);
    applyChannelPolicy(session, channels, client);
    channels.put(EdcMfaChannelsAuthenticator.NOTE_ENROLMENT_REQUIRED,
        enrolmentRequired(session, user, channels, client) ? "1" : "0");
    return channels;
  }

/**
   * Whether this person still owes an enrolment.
   *
   * <p>Two reasons, and only two: they have no working channel at all, which is the question
   * {@link #hasNoUsableChannel} answers, or ICT has marked one or more channels as required and they
   * do not have <em>all</em> of them.
   *
   * <p>Every required channel has to be present, not one of them. A user who has Telegram while this
   * realm also requires the authenticator app is still owed an enrolment - that is what "required"
   * means, and reading it as "any one of them" would let a requirement be satisfied by a channel
   * somebody set up for an unrelated reason. Email is the documented exception: a user with no
   * address on file is not held to it, because the option is not on their screen either.
   *
   * <p>{@code required} is read from the realm rather than passed in, so there is one answer to this
   * question in the codebase and no caller can compute a looser version of it.
   */
  public static boolean enrolmentRequired(KeycloakSession session, UserModel user,
      Map<String, String> channels) {
    return enrolmentRequired(session, user, channels, null);
  }

  /**
   * Client-aware overload: required channels come from the client's policy (or the realm default).
   */
  public static boolean enrolmentRequired(KeycloakSession session, UserModel user,
      Map<String, String> channels, ClientModel client) {
    if (hasNoUsableChannel(channels)) {
      return true;
    }
    RealmModel realm = session == null || session.getContext() == null ? null
        : session.getContext().getRealm();
    return requiredPending(session, user, channels, EdcChannelPolicy.requiredFor(client, realm));
  }

  /**
   * Whether a channel this person can use is required and not set up.
   *
   * <p>The exemption is the whole point of this method. A required channel the user has no way to
   * reach - Email when they have no address on file, Telegram when the bot is not configured on this
   * deployment - is not held against them: they cannot see the option either, and demanding a second
   * step behind a row that is not on their screen would put a few thousand people into a wizard they
   * cannot leave. Demanding enrolment for something unreachable is the one outcome this must never
   * produce, so the unreachable case always resolves to "not pending".
   *
   * <p>Note the deliberate asymmetry with Telegram being <em>undeliverable</em>: a user with a
   * Telegram link but no SPASS token reads as Telegram inactive, and that still counts as pending -
   * that is the state they are meant to fix by linking one, not a reason to let them off.
   */
  static boolean requiredPending(KeycloakSession session, UserModel user, Map<String, String> channels,
      java.util.Set<String> required) {
    return !pendingRequiredChannels(session, user, channels, required).isEmpty();
  }

  /**
   * The required channels this person still owes, in display order.
   *
   * <p>The same rule as {@link #requiredPending}, returning the set rather than a boolean, because
   * two callers need more than the answer: the sign-in path wants the yes/no, and the enrolment
   * chooser has to put a "Required" badge on exactly these rows. A badge on a row the person cannot
   * act on - email with no address on file - contradicts the exemption this method exists to apply,
   * and the contradiction is on the screen they are being asked to act on.
   *
   * @return the outstanding required channels, empty when nothing is owed
   */
  public static java.util.Set<String> pendingRequiredChannels(KeycloakSession session, UserModel user,
      Map<String, String> channels, java.util.Set<String> required) {
    java.util.Set<String> pending = new java.util.LinkedHashSet<>();
    if (required == null || required.isEmpty()) {
      return pending;
    }
    for (String channel : required) {
      if (!usableBy(session, user, channel)) {
        continue;
      }
      if (!isOn(channels, noteForChannel(channel))) {
        pending.add(channel);
      }
    }
    return pending;
  }

  /**
   * Whether this person could set this channel up at all, regardless of whether they have.
   *
   * <p>Only Email and Telegram can be unreachable. TOTP needs nothing arranged in advance: no
   * address, no bot, no phone to receive anything on, which is also why it is the one channel that is
   * safe to require of everybody.
   *
   * <p>Backup codes are never "usable" in this sense, and that is deliberate rather than an
   * oversight. The wizard issues them itself, as its last step, and only once the person has
   * satisfied everything else - so treating them as outstanding would make the wizard wait on a
   * channel it will not produce until it stops waiting, and no one would ever finish enrolling. A
   * policy that names {@code backupCode} as required therefore has no effect on anyone, which is why
   * {@link EdcChannelPolicy#isSatisfiable} refuses to let one be stored.
   */
  private static boolean usableBy(KeycloakSession session, UserModel user, String channel) {
    if (EdcChannelPolicy.EMAIL.equals(channel)) {
      return hasEmailAddress(user);
    }
    if (EdcChannelPolicy.TELEGRAM.equals(channel)) {
      return session != null && isTelegramConfigured(session);
    }
    return !EdcChannelPolicy.BACKUP_CODE.equals(channel);
  }

  /** The detection note a channel's state is carried in. */
  static String noteForChannel(String channel) {
    return switch (channel) {
      case EdcChannelPolicy.EMAIL -> EdcMfaChannelsAuthenticator.NOTE_EMAIL;
      case EdcChannelPolicy.TELEGRAM -> EdcMfaChannelsAuthenticator.NOTE_TELEGRAM;
      case EdcChannelPolicy.TOTP -> EdcMfaChannelsAuthenticator.NOTE_TOTP;
      case EdcChannelPolicy.BACKUP_CODE -> EdcMfaChannelsAuthenticator.NOTE_BACKUP_CODE;
      default -> channel;
    };
  }

  /**
   * Turns off every channel ICT has switched off for this realm.
   *
   * <p>Applied last, inside {@link #detect}, so there is one place where the answer is computed and
   * every reader agrees. Detection asks "can this user be reached on this channel"; this asks "is
   * this channel permitted at all", which is a different question with a different owner. Doing it
   * here rather than in each reader is what stops the login chooser, the OTP page, the enrolment
   * wizard and the account console from disagreeing - and disagreement in that direction is a
   * bypass, because a channel that one screen still offers is a channel a user can enrol on.
   *
   * <p>After this, {@link #hasNoUsableChannel} reports a user whose only remaining channel is
   * disabled as owing enrolment, which is the correct answer: there is genuinely no way in.
   *
   * <p>Separate from the logging wrapper so the rule can be pinned by a test over a plain map.
   *
   * @param policy the channels ICT has left on; all four means no change
   * @return whether anything was switched off
   */
  static boolean applyPolicy(Map<String, String> channels, Set<String> policy) {
    if (policy == null || policy.containsAll(EdcChannelPolicy.all())) {
      return false;
    }
    boolean changed = false;
    changed |= withdraw(channels, EdcMfaChannelsAuthenticator.NOTE_EMAIL, policy, EdcChannelPolicy.EMAIL);
    changed |= withdraw(channels, EdcMfaChannelsAuthenticator.NOTE_TOTP, policy, EdcChannelPolicy.TOTP);
    changed |=
        withdraw(channels, EdcMfaChannelsAuthenticator.NOTE_TELEGRAM, policy, EdcChannelPolicy.TELEGRAM);
    changed |= withdraw(channels, EdcMfaChannelsAuthenticator.NOTE_BACKUP_CODE, policy,
        EdcChannelPolicy.BACKUP_CODE);
    return changed;
  }

  /** Withdraws one channel when its note is on and the policy does not include it. */
  private static boolean withdraw(Map<String, String> channels, String note, Set<String> policy,
      String channel) {
    if (policy.contains(channel) || !"1".equals(channels.get(note))) {
      return false;
    }
    channels.put(note, "0");
    // The masked address is only meaningful while Email is on. Leaving it would let a reader that
    // shows the badge rather than the flag advertise an address for a switched-off channel.
    if (EdcChannelPolicy.EMAIL.equals(channel)) {
      channels.remove(EdcMfaChannelsAuthenticator.NOTE_EMAIL_MASKED);
    }
    return true;
  }

  /** Reads the realm's policy and applies it. */
  private static void applyChannelPolicy(KeycloakSession session, Map<String, String> channels) {
    applyChannelPolicy(session, channels, null);
  }

  /**
   * Client-aware overload: applies the client's policy (or realm default) to the detected channels.
   */
  private static void applyChannelPolicy(KeycloakSession session, Map<String, String> channels,
      ClientModel client) {
    RealmModel realm = session == null || session.getContext() == null ? null
        : session.getContext().getRealm();
    Set<String> enabled = EdcChannelPolicy.enabledFor(client, realm);
    if (applyPolicy(channels, enabled)) {
      log.infof("method=applyChannelPolicy client=%s enabled=%s message=Channels switched off by policy",
          client == null ? "default" : client.getClientId(), enabled);
    }
  }

  /**
   * Turns the Telegram channel off for a user the bot could not actually reach.
   *
   * <p>A Telegram link is not a channel, it is an address. Something still has to put a code in
   * front of the bot: enrolment creates a {@code spass} token for exactly this, and the bot sends
   * the PIN for it. Delete that token - which is what privacyIDEA's own web UI does, in one click -
   * and the link survives while the delivery path does not. Reporting the channel as available then
   * has two bad effects at once: the user is told they have a second step when they do not, and
   * because a marker plus any channel reads as "enrolled", {@code requiresEnrolment} returns false
   * and they are signed straight in with no second factor at all.
   *
   * <p>Fails closed. If privacyIDEA cannot be asked - outage, no admin token, the admin API hanging
   * behind {@code /token/} - the channel is withdrawn. The alternative failure is a silent
   * hole, and the cost of failing closed is that people are asked to enrol again, which is the
   * safe direction to be wrong in.
   */
  private static void suppressUndeliverableTelegram(UserModel user,
    Map<String, String> channels) {
    if (!withdrawUndeliverableTelegram(channels)) {
      return;
    }
    log.infof("method=suppressUndeliverableTelegram user=%s "
        + "message=Telegram is linked but privacyIDEA holds no token to deliver a code, "
        + "so the channel is withdrawn and enrolment is owed again",
      user == null ? null : user.getUsername());
  }

  /**
   * Withdraws the Telegram channel unless privacyIDEA can deliver through it.
   *
   * <p>Separate from the logging wrapper above so the rule can be pinned by a test without a
   * session, a user or a network.
   *
   * @return whether the channel was withdrawn
   */
  static boolean withdrawUndeliverableTelegram(Map<String, String> channels) {
    if (!"1".equals(channels.get(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM))) {
      return false;
    }
    if ("1".equals(channels.get(KEY_SPASS_TOKEN))) {
      return false;
    }
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM, "0");
    return true;
  }

  /**
   * Whether the user has no way at all to obtain a code.
   *
   * <p>Only the channels that can actually deliver or verify something count. Every one of them needs
   * a privacyIDEA token, Telegram included: the bot can only send a code for a token that exists, so
   * a bare link is an address rather than a channel. See
   * {@link #suppressUndeliverableTelegram(UserModel, Map)}.
   *
   * <p>When this is true the OTP page has nothing to show and nothing the user can do, so the page
   * has to say so rather than present an empty code field.
   */
  static boolean hasNoUsableChannel(Map<String, String> channels) {
    return !isOn(channels, EdcMfaChannelsAuthenticator.NOTE_TELEGRAM)
      && !isOn(channels, EdcMfaChannelsAuthenticator.NOTE_EMAIL)
      && !isOn(channels, EdcMfaChannelsAuthenticator.NOTE_TOTP)
      && !isOn(channels, EdcMfaChannelsAuthenticator.NOTE_BACKUP_CODE);
  }

  private static boolean isOn(Map<String, String> channels, String note) {
    return "1".equals(channels.get(note));
  }

  /**
   * Whether Telegram can be offered as a channel at all.
   *
   * <p>Distinct from {@link #telegramChatId}: that answers "is this user linked", this answers "is
   * the thing that links them configured". Enrolment needs the second to decide whether to show the
   * row at all, and offering it on a realm with no bot would dead-end the user at a QR code that
   * cannot work.
   *
   * <p>Checks the token's <em>shape</em> as well as its presence. A placeholder value - which is what
   * a realm carries until someone pastes in the real one - is not blank, so a presence check passes
   * it and the chooser offers a channel that cannot ever deliver a code. The failure would happen on
   * the user's phone, where no explanation can be shown to them, so it is caught here instead.
   */
  public static boolean isTelegramConfigured(KeycloakSession session) {
    if (session == null || session.getContext() == null
      || session.getContext().getRealm() == null) {
      return false;
    }
    try {
      IdentityProviderModel idp = session.identityProviders().getByAlias(TELEGRAM_IDP_ALIAS);
      if (idp == null) {
        return false;
      }
      String botToken = new OAuth2IdentityProviderConfig(idp).getClientSecret();
      String botUsername = idp.getConfig() == null ? null : idp.getConfig().get("clientId");
      if (isBlank(botToken) || isBlank(botUsername)) {
        return false;
      }
      if (!looksLikeBotToken(botToken)) {
        log.warnf("method=isTelegramConfigured bot=%s reason=NotABotToken "
          + "message=Set clientSecret on the telegram identity provider to the token BotFather gave "
          + "you; Telegram will not be offered until then", botUsername);
        return false;
      }
      return true;
    } catch (Exception e) {
      log.warnf("method=isTelegramConfigured error=%s", e.getMessage());
      return false;
    }
  }

  private static boolean isBlank(String value) {
    return value == null || value.isBlank();
  }

  /**
   * Whether an email channel could be set up for this user.
   *
   * <p>About having an address, not about already holding a token: at enrolment time nobody holds a
   * token, so asking about tokens would mark the channel unavailable for everyone. Most staff in
   * this workforce have no address at all, and that is the case the enrolment screen has to say out
   * loud rather than offer and then fail.
   */
  public static boolean hasEmailAddress(UserModel user) {
    String email = user == null ? null : user.getFirstAttribute("email");
    if (email != null && !email.isBlank()) {
      return true;
    }
    return user != null && user.getEmail() != null && !user.getEmail().isBlank();
  }

  /**
   * Telegram counts as available when the user has a linked Telegram identity.
   *
   * The link is detected from the federated identity rather than a {@code telegram-user-id}
   * attribute: this realm federates to LDAP with editMode=Writable, which discards attributes that
   * are not mapped in the directory, so a locally written attribute silently disappears. The
   * federated-identity row is managed by Keycloak itself and survives LDAP sync.
   */
  private static void detectTelegram(KeycloakSession session, UserModel user,
    Map<String, String> channels) {
    String chatId = telegramChatId(session, user);
    if (chatId == null) {
      return;
    }
    UserModel other = anotherUserHolding(session, user, chatId);
    if (other != null) {
      // Two accounts claiming one Telegram chat. Codes for either of them would be delivered to
      // the same phone, so neither may be told the channel is theirs. Logged loudly because it means
      // the link guard was bypassed somewhere, and this is the state that must be repaired by hand.
      log.errorf("method=detectTelegram user=%s chat=%s alsoHeldBy=%s "
          + "message=Two accounts claim one Telegram account; refusing the channel for both",
        user.getUsername(), chatId, other.getUsername());
      return;
    }
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM, "1");
    // Prefer the Telegram handle for display; fall back to the chat id because a Telegram account
    // need not have a username set.
    String handle = user.getFirstAttribute(TELEGRAM_USERNAME_ATTR);
    if (handle == null || handle.isBlank()) {
      handle = telegramUsername(session, user);
    }
    channels.put(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM_HANDLE,
      handle == null || handle.isBlank() ? chatId : handle);
    // Without this the page would advertise a channel the sender cannot deliver to.
    channels.put(EdcMfaChannelsAuthenticator.NOTE_MASKED, "1");
  }

  /**
   * Another account that already claims the same Telegram chat.
   *
   * <p>Checks the user attribute as well as the federated identity, because the attribute is the one
   * that persists on this realm: the {@code telegram} identity provider writes it in process, while
   * a federated-identity row on an LDAP-backed user does not reliably survive. Checking only the
   * row meant a second account could be linked to a chat that was already in use - the codes for
   * both would then be delivered to one phone.
   *
   * @return the other user, or {@code null} when this is the only claimant
   */
  public static UserModel anotherUserHolding(KeycloakSession session, UserModel user,
    String chatId) {
    if (session == null) {
      return null;
    }
    RealmModel realm = session.getContext().getRealm();
    if (realm == null || user == null || chatId == null || chatId.isBlank()) {
      return null;
    }
    try {
      UserModel owner = FederatedIdentity.getUserByTelegram(session, TELEGRAM_IDP_ALIAS, chatId);
      if (owner != null && !owner.getId().equals(user.getId())) {
        return owner;
      }
      try (Stream<UserModel> claimants =
        session.users().searchForUserByUserAttributeStream(realm, TELEGRAM_USER_ID_ATTR, chatId)) {
        return claimants
          .filter(candidate -> !candidate.getId().equals(user.getId()))
          .findFirst()
          .orElse(null);
      }
    } catch (Exception e) {
      log.warnf("method=anotherUserHolding user=%s chat=%s error=%s", user.getUsername(), chatId,
        e.getMessage());
      return null;
    }
  }

  /**
   * The @username of the linked Telegram account, or {@code null} if it has none.
   */
  static String telegramUsername(KeycloakSession session, UserModel user) {
    if (session == null || session.getContext().getRealm() == null) {
      return null;
    }
    try {
      return session.users()
        .getFederatedIdentitiesStream(session.getContext().getRealm(), user)
        .filter(id -> TELEGRAM_IDP_ALIAS.equals(id.getIdentityProvider()))
        .map(FederatedIdentityModel::getUserName)
        .filter(name -> name != null && !name.isBlank())
        .findFirst()
        .orElse(null);
    } catch (Exception e) {
      log.warnf("method=telegramUsername user=%s error=%s", user.getUsername(), e.getMessage());
      return null;
    }
  }

  /**
   * @return the Telegram chat id of the user's linked Telegram account, or {@code null} when not
   * linked or the stored identity does not carry a usable Telegram id
   */
  public static String telegramChatId(KeycloakSession session, UserModel user) {
    String attribute = user.getFirstAttribute(TELEGRAM_USER_ID_ATTR);
    if (attribute != null && !attribute.isBlank()) {
      return attribute;
    }
    if (session == null || session.getContext().getRealm() == null) {
      return null;
    }
    try {
      return session.users()
        .getFederatedIdentitiesStream(session.getContext().getRealm(), user)
        .filter(id -> TELEGRAM_IDP_ALIAS.equals(id.getIdentityProvider()))
        .map(FederatedIdentityModel::getUserId)
        .filter(id -> id != null && !id.isBlank())
        .findFirst()
        .orElse(null);
    } catch (Exception e) {
      log.warnf("method=telegramChatId user=%s error=%s", user.getUsername(), e.getMessage());
      return null;
    }
  }

  private static void detectPrivacyIdeaTokens(PrivacyIdeaService privacyIdea, UserModel user,
    Map<String, String> channels) {
    if (privacyIdea == null) {
      log.warn("method=detectPrivacyIdeaTokens reason=serviceNotConfigured");
      return;
    }
    String username = user.getUsername();
    if (username == null || username.isBlank()) {
      return;
    }

    try {
      String adminToken = privacyIdea.getPrivacyIdeaAuthToken();
      if (adminToken == null || adminToken.isBlank()) {
        log.warnf("method=detectPrivacyIdeaTokens user=%s reason=noAdminToken", username);
        return;
      }

      if (!privacyIdea.getActiveTokenSerials(username, "spass", adminToken).isEmpty()) {
        channels.put(KEY_SPASS_TOKEN, "1");
        channels.put(EdcMfaChannelsAuthenticator.NOTE_EMAIL, "1");
        String masked = maskEmail(user.getFirstAttribute("email"));
        if (masked != null) {
          channels.put(EdcMfaChannelsAuthenticator.NOTE_EMAIL_MASKED, masked);
        }
      }

      for (String type : List.of("hotp", "totp")) {
        if (!privacyIdea.getActiveTokenSerials(username, type, adminToken).isEmpty()) {
          channels.put(EdcMfaChannelsAuthenticator.NOTE_TOTP, "1");
          break;
        }
      }

      // A TAN token is a pre-printed list of single-use 6-digit codes, which is exactly a set of
      // backup codes. They are typed into the same OTP field, and privacyIDEA validates them through
      // the ordinary /validate/check call the authenticator already makes, so no extra validation
      // path is needed here - only the signal that the channel exists.
      if (!privacyIdea.getActiveTokenSerials(username, "tan", adminToken).isEmpty()) {
        channels.put(EdcMfaChannelsAuthenticator.NOTE_BACKUP_CODE, "1");
      }
    } catch (Exception e) {
      log.errorf("method=detectPrivacyIdeaTokens user=%s error=%s", username, e.getMessage());
    }
  }

  /**
   * Hides all but the first and last character of the local part, e.g. {@code s•••a@edc.com.kh}.
   *
   * <p>Returns {@code null} when the value is not an address at all. Callers show no badge in that
   * case, which is the honest outcome: an address too malformed to mask is also an address too
   * malformed to send a code to, and half-masking it would put a string on screen that looks like
   * an address but reaches nobody.
   */
  static String maskEmail(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    int at = value.indexOf('@');
    if (at <= 0 || at == value.length() - 1) {
      return null;
    }
    String local = value.substring(0, at);
    String domain = value.substring(at);
    String head = local.substring(0, 1);
    String tail = local.length() > 2 ? local.substring(local.length() - 1) : "";
    int hidden = Math.max(1, local.length() - head.length() - tail.length());
    return head + "\u2022".repeat(hidden) + tail + domain;
  }
}