package com.khalibre.keycloak.provider.edc;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;

/**
 * Which MFA channels ICT has switched on for this realm.
 *
 * <p>Stored as a single realm attribute rather than four booleans, so a change is atomic: there is no
 * window in which a half-written update has left the realm with nothing enabled.
 *
 * <p><strong>The default is every channel on.</strong> An absent, blank or unrecognised value is
 * treated as "no restriction", which is the direction that is safe to be wrong in - a typo in the
 * attribute cannot silently lock several thousand people out of their accounts. Turning channels off
 * is always an explicit act.
 *
 * <p>The same two attributes carry the per-client overrides ({@link #enabledFor}), so a realm-wide
 * policy and one application's own policy are the same concept read from two different homes rather
 * than two parallel mechanisms.
 */
public final class EdcChannelPolicy {

  private static final Logger log = Logger.getLogger(EdcChannelPolicy.class);

  /** Realm attribute holding the comma-separated list of enabled channels. */
  public static final String ATTRIBUTE = "edc-mfa-enabled-channels";

  /**
   * Realm attribute holding the comma-separated list of channels a user must have set up.
   *
   * <p>Separate from {@link #ATTRIBUTE} rather than folded into it, so that a realm configured before
   * this existed keeps working and reads as "nothing is required" - which is what an absent attribute
   * has to mean, since demanding enrolment is not something an attribute's absence may do.
   *
   * <p>A required channel is always also enabled. The two are normalised together on read and on
   * write, so a realm can never demand a second step that it has also forbidden.
   */
  public static final String ATTRIBUTE_REQUIRED = "edc-mfa-required-channels";

  /**
   * Attribute on a <em>client</em> recording when its own policy was last written.
   *
   * <p>Only ever set on a per-application policy, never on the realm: the realm default has no
   * "changed" moment worth showing, because it applies to everything at once. Named here so the
   * admin endpoint's read and its write cannot drift onto two different spellings of it, which is
   * how a "Last changed" column silently becomes permanently blank.
   */
  public static final String ATTRIBUTE_UPDATED = "edc-mfa-policy-updated";

  /** The four channels ICT can control. Names are the ones the rest of the code already uses. */
  public static final String EMAIL = "email";
  public static final String TELEGRAM = "telegram";
  public static final String TOTP = "totp";
  public static final String BACKUP_CODE = "backupCode";

  /** The four channels ICT can control, in the order they are rendered and stored. */
  private static final List<String> ORDERED =
      List.of(EMAIL, TELEGRAM, TOTP, BACKUP_CODE);

  private static final Set<String> ALL = Set.copyOf(ORDERED);

/**
   * Clients Keycloak owns whose channel policy could never be read, so listing them would be a row
   * that cannot be acted on.
   *
   * <p>The test is not "built-in" - it is "is this ever the {@code azp} of a token whose channels
   * are read?". {@code account-console} is deliberately <em>absent</em>: it is the client the
   * account console authenticates with, so a policy on it is exactly what governs the self-service
   * MFA page, and it is the one built-in an administrator genuinely wants to configure.
   *
   * <p>What is here instead are the resource servers and the machine-to-machine ids. {@code account}
   * and {@code realm-management} are API servers - the token names them as {@code aud} and never as
   * {@code azp} - {@code admin-cli} and {@code broker} never run the browser MFA flow, and none of
   * them can be the caller whose channels {@link EdcChannelDetector} inspects. A policy on any of
   * them would be stored, shown in the admin table, and do nothing at all.
   *
   * <p>Earlier this set wrongly included {@code account-console} on the belief that Keycloak
   * reconciles built-in client attributes and would erase the policy. Measured, and it does not:
   * {@code edc-mfa-*} attributes written on that client survived two full restarts untouched.
   */
private static final Set<String> BUILT_IN_CLIENT_IDS = Set.of("account",
      "admin-cli", "broker", "realm-management", "security-admin-console");

  private EdcChannelPolicy() {
  }

  /**
   * @return the enabled channels, in a stable order; all four when the realm says nothing
   */
  public static Set<String> enabled(RealmModel realm) {
    if (realm == null) {
      return ALL;
    }
    String raw;
    try {
      raw = realm.getAttribute(ATTRIBUTE);
    } catch (Exception e) {
      log.warnf("key=%s error=%s message=Cannot read the attribute; treating every channel as on",
          ATTRIBUTE, e.getMessage());
      return ALL;
    }
    return parse(raw);
  }

  /**
   * Parses the attribute value.
   *
   * <p>Separate from {@link #enabled(RealmModel)} and static over a plain string so the rules can be
   * pinned by a test without a realm, which is the only kind of test this module has.
   *
   * @return the enabled channels, or all four when the value is absent, blank or wholly unrecognised
   */
  public static Set<String> parse(String raw) {
    if (raw == null || raw.isBlank()) {
      return ALL;
    }
    Set<String> enabled = new LinkedHashSet<>();
    for (String part : raw.split(",")) {
      String name = part.trim();
      if (name.isEmpty()) {
        continue;
      }
      // Case-insensitive on input, canonical on output: the account console and the admin endpoint
      // both speak the lowercase names, but a hand-edited attribute should not silently do nothing.
      String canonical = canonical(name);
      if (canonical == null) {
        log.warnf("key=%s value=%s message=Not a channel name; ignoring it", ATTRIBUTE, name);
        continue;
      }
      enabled.add(canonical);
    }
    // An attribute that parses to nothing usable is treated as absent rather than as "disable
    // everything". Disabling all four would push every user into an enrolment wizard with no
    // channel to pick, so that outcome has to be impossible to reach by accident.
    if (enabled.isEmpty()) {
      log.warnf("key=%s value=%s message=No recognisable channel; treating every channel as on",
          ATTRIBUTE, raw);
      return ALL;
    }
    return enabled;
  }

  /** @return the canonical name, or {@code null} when the input is not one of the four */
  static String canonical(String name) {
    String lower = name.toLowerCase(Locale.ROOT);
    if (BACKUP_CODE.equalsIgnoreCase(lower) || "backup-code".equals(lower)
        || "backup_code".equals(lower) || "tan".equals(lower)) {
      return BACKUP_CODE;
    }
    if (EMAIL.equals(lower)) {
      return EMAIL;
    }
    if (TELEGRAM.equals(lower)) {
      return TELEGRAM;
    }
    if (TOTP.equals(lower) || "authenticator".equals(lower) || "app".equals(lower)) {
      return TOTP;
    }
    return null;
  }

  /**
   * Whether ICT has left this channel on for an application.
   *
   * <p>Client-scoped, and deliberately the only overload: a realm-only `isEnabled(realm, channel)`
   * existed beside this one and was the obvious thing to reach for when adding a check, while
   * answering with the realm's policy even where an application had its own. A caller that gets that
   * wrong fails in one direction - the page still offers a channel the application switched off - so
   * the narrow signature is the point. {@link #enabledFor} is what reads the realm default; the
   * per-application methods all funnel through here.
   */
  public static boolean isEnabled(ClientModel client, RealmModel realm, String channel) {
    String canonical = canonical(channel);
    if (canonical == null) {
      return true;
    }
    return enabledFor(client, realm).contains(canonical);
  }

  /** Every channel name, in display order, for a control that shows all four. */
  public static List<String> all() {
    return ORDERED;
  }

  /**
   * The enabled channels a user could actually be offered during enrolment.
   *
   * <p>Backup codes are not one of them: privacyIDEA issues them at the end of the wizard, so there
   * is no row to pick. That makes a policy of {@code backupCode} alone one nobody can satisfy - the
   * enrolment chooser would render with every row switched off and the wizard would dead-end - so the
   * admin endpoint refuses to store one.
   */
  public static Set<String> selectableFrom(Set<String> enabled) {
    Set<String> selectable = new LinkedHashSet<>();
    if (enabled == null) {
      return selectable;
    }
    for (String channel : ORDERED) {
      if (enabled.contains(channel) && !BACKUP_CODE.equals(channel)) {
        selectable.add(channel);
      }
    }
    return selectable;
  }

  /** Whether this set leaves somebody at least one channel they could set up. */
  public static boolean isSatisfiable(Set<String> enabled) {
    return !selectableFrom(enabled).isEmpty();
  }

  /**
   * The channels a user is required to have set up, in a stable order.
   *
   * <p>Intersected with what is enabled. That is the direction that is safe to be wrong in: a realm
   * whose only required channel was switched off afterwards must not start demanding a second step
   * that nobody can complete, so the requirement lapses and is logged rather than trapping the
   * population. The admin console refuses that combination outright - see
   * {@code EdcMfaAdminResource#setChannels} - so the state is only reachable by hand.
   */
  public static Set<String> required(RealmModel realm) {
    if (realm == null) {
      return Collections.emptySet();
    }
    Set<String> asked = parseAttribute(realm, ATTRIBUTE_REQUIRED);
    return intersectWithEnabled(asked, enabled(realm));
  }

  // ------------------------------------------------------------ per-client policy
  //
  // An application - a Keycloak client - may carry its own policy in the same two attribute names,
  // stored on the client. A client with neither attribute set inherits the realm's, which is what
  // makes the whole feature safe to adopt: an application nobody has looked at behaves exactly as it
  // did before this existed, and switching one application's policy on cannot change another's.

  /**
   * Whether this application has a policy of its own.
   *
   * <p>Either attribute is enough. One without the other is a half-finished edit, so it counts as an
   * override rather than as inherited - an application should never look configured while behaving
   * as though it were not.
   */
  public static boolean hasOwnPolicy(ClientModel client) {
    return client != null
        && (notBlank(client.getAttribute(ATTRIBUTE)) || notBlank(client.getAttribute(ATTRIBUTE_REQUIRED)));
  }

  /** The enabled channels for this application, or the realm's where it has none of its own. */
  public static Set<String> enabledFor(ClientModel client, RealmModel realm) {
    String raw = client == null ? null : client.getAttribute(ATTRIBUTE);
    // Only the enabled list overrides it. A client that names no enabled channel of its own inherits
    // both halves of the realm's, because an absent attribute is how "not configured here" is
    // spelled - see hasOwnPolicy() for why that still counts as an override when the *other*
    // attribute is present.
    return notBlank(raw) ? parse(raw) : enabled(realm);
  }

  /**
   * The required channels for this application, or the realm's where it has none of its own.
   *
   * <p>An override that sets only the enabled list means <em>second step optional</em> - the same
   * thing an application configured with channels and no requirement means everywhere else. It does
   * not fall back to the realm's required list, because inheriting a requirement the application did
   * not ask for is the more damaging of the two mistakes: it stops people signing in to that
   * application, and the application is not the thing anyone would go and look at.
   */
  public static Set<String> requiredFor(ClientModel client, RealmModel realm) {
    if (!hasOwnPolicy(client)) {
      return required(realm);
    }
    return intersectWithEnabled(namesIn(client.getAttribute(ATTRIBUTE_REQUIRED)),
        enabledFor(client, realm));
  }

  /**
   * Drops required channels that are switched off.
   *
   * <p>Shared by both homes, so a per-application policy cannot demand a step it has also forbidden
   * any more than the realm's can.
   */
  private static Set<String> intersectWithEnabled(Set<String> required, Set<String> enabled) {
    if (required.isEmpty() || (required.size() == enabled.size() && enabled.containsAll(required))) {
      return required;
    }
    Set<String> usable = new LinkedHashSet<>();
    for (String channel : ORDERED) {
      if (required.contains(channel) && enabled.contains(channel)) {
        usable.add(channel);
      }
    }
    if (usable.size() != required.size()) {
      log.warnf("key=%s required=%s enabled=%s message=Dropping a required channel that is switched "
          + "off, so nobody is left owing a second step they cannot complete", ATTRIBUTE_REQUIRED,
          required, enabled);
    }
    return usable;
  }

  /** The channel names in an attribute value, ignoring anything unrecognisable. */
  private static Set<String> namesIn(String raw) {
    Set<String> names = new LinkedHashSet<>();
    if (raw == null || raw.isBlank()) {
      return names;
    }
    for (String part : raw.split(",")) {
      String canonical = canonical(part.trim());
      if (canonical != null) {
        names.add(canonical);
      } else if (!part.isBlank()) {
        log.warnf("value=%s message=Not a channel name; ignoring it", part.trim());
      }
    }
    return names;
  }

  private static boolean notBlank(String value) {
    return value != null && !value.isBlank();
  }

  /** The raw value stored for this application, for the admin page to show as "inherited". */
  public static String ownEnabledAttribute(ClientModel client) {
    return client == null ? null : client.getAttribute(ATTRIBUTE);
  }

  public static String ownRequiredAttribute(ClientModel client) {
    return client == null ? null : client.getAttribute(ATTRIBUTE_REQUIRED);
  }

  /** The clients a policy can be written for: everything enabled whose channels are ever read. */
  public static List<ClientModel> configurableClients(RealmModel realm) {
    List<ClientModel> clients = new ArrayList<>();
    for (ClientModel client : realm.getClientsStream().toList()) {
      if (client.isEnabled() && !isBuiltInClientId(client.getClientId())) {
        clients.add(client);
      }
    }
    clients.sort(Comparator
        .comparing((ClientModel c) -> c.getName() == null || c.getName().isBlank()
            ? c.getClientId() : c.getName(), String.CASE_INSENSITIVE_ORDER)
        .thenComparing(ClientModel::getClientId));
    return clients;
  }

  /**
   * Whether a client ID is one whose channel policy could never be read.
   *
   * <p>Not merely a tidiness rule, and no longer "Keycloak owns the row" - measured, the server does
   * not reconcile built-in client attributes. The test is whether the id can ever be the {@code azp}
   * of a token whose channels {@link EdcChannelDetector} inspects, which excludes the resource
   * servers and the machine-to-machine ids. Listing them would offer an administrator a switch that
   * stores a value and changes nothing, and a row that cannot be acted on is worse than no row.
   *
   * <p>{@code account-console} is deliberately not here, and {@link #BUILT_IN_CLIENT_IDS} explains
   * why.
   */
  public static boolean isBuiltInClientId(String clientId) {
    return clientId != null && BUILT_IN_CLIENT_IDS.contains(clientId);
  }

  /** Reads one channel-list attribute, treating anything unusable as "not set". */
  private static Set<String> parseAttribute(RealmModel realm, String key) {
    if (realm == null) {
      return Set.of();
    }
    String raw;
    try {
      raw = realm.getAttribute(key);
    } catch (Exception e) {
      log.warnf("key=%s error=%s message=Cannot read the attribute; treating it as unset", key,
          e.getMessage());
      return Set.of();
    }
    // Deliberately not parse(): an absent or unrecognised required list must read as "nothing is
    // required", where parse() would answer "everything" - the opposite of the safe direction here.
    Set<String> names = new LinkedHashSet<>();
    if (raw == null || raw.isBlank()) {
      return names;
    }
    for (String part : raw.split(",")) {
      String canonical = canonical(part.trim());
      if (canonical != null) {
        names.add(canonical);
      } else if (!part.isBlank()) {
        log.warnf("key=%s value=%s message=Not a channel name; ignoring it", key, part.trim());
      }
    }
    return names;
  }

/**
 * Serialises a set of channels for storage.
 *
 * @throws IllegalArgumentException when the set is empty, naming the reason
 */
public static String serialise(Set<String> channels) {
    return serialise(channels, ATTRIBUTE, true);
  }

  /**
   * Serialises a required-channel list. Unlike the enabled one this may legitimately be empty - that
   * is how an admin says "nothing is required" - so it does not refuse.
   */
  public static String serialiseRequired(Set<String> channels) {
    return serialise(channels, ATTRIBUTE_REQUIRED, false);
  }

  private static String serialise(Set<String> channels, String key, boolean refuseEmpty) {
    if (channels == null || channels.isEmpty()) {
      if (refuseEmpty) {
        throw new IllegalArgumentException("At least one MFA channel must stay enabled");
      }
      return "";
    }
    StringBuilder value = new StringBuilder();
    for (String name : ORDERED) {
      if (channels.contains(name)) {
        if (value.length() > 0) {
          value.append(',');
        }
        value.append(name);
      }
    }
    if (value.length() == 0) {
      // Every name in the input was unrecognised, so this would have stored an attribute that
      // parses back to "all on" - reporting success for a change that did nothing.
      throw new IllegalArgumentException("No recognisable channel in the request");
    }
    return value.toString();
  }
}