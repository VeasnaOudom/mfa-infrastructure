package com.khalibre.keycloak.provider.edc;

import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.MultivaluedMap;

import org.jboss.logging.Logger;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import com.khalibre.keycloak.provider.privacyIdea.PrivacyIdeaSettings;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;

/**
 * Stops a user who has no second step and walks them through setting one up, in one pass.
 *
 * <p>Driven as a required action rather than as a flow execution, because that is what makes it
 * block: Keycloak will not finish signing a user in while an action is outstanding, and the
 * accompanying {@code edc-mfa-enrolled} condition keeps the privacyIDEA challenge from running at
 * all while the wizard is in progress. Otherwise the user meets a six-box code field before ever
 * being told they have to set something up.
 *
 * <p>Ends by issuing backup codes automatically. That is not an option the user gets to decline: a
 * staff member with no email address whose phone is lost has nothing else, and the alternative is
 * the queue at the ICT desk that this whole thing exists to avoid.
 *
 * <p>Wizard position lives in authentication-session notes rather than in the model. The material
 * those notes carry - the enrolment URI of a half-registered authenticator token, the one and only
 * copy of a set of backup codes - must not be readable from a template or a URL, and auth notes are
 * server-side. The templates get their data through form attributes instead, because FreeMarker
 * cannot see auth notes at all.
 */
public class EdcMfaEnrolmentRequiredAction
    implements org.keycloak.authentication.RequiredActionProvider {

  private static final Logger log = Logger.getLogger(EdcMfaEnrolmentRequiredAction.class);

  public static final String PROVIDER_ID = "edc-mfa-enrolment";

  /** Wizard position. Absent means the wizard has not started in this session. */
  static final String NOTE_STEP = "edc_enrol_step";

  /** The channel being set up, for the record written on completion. */
  static final String NOTE_CHANNEL = "edc_enrol_channel";

  /** Serial of the token enrolled by the current step, deleted once the step succeeds. */
  static final String NOTE_SERIAL = "edc_enrol_serial";

  /** Enrolment URI of a half-registered token, shown as a QR code and then discarded. */
  static final String NOTE_TOKEN_URI = "edc_enrol_token_uri";

  /**
   * The issued codes. privacyIDEA stores them hashed, so this note holds the only copy that will
   * ever exist, and it is dropped the moment the user leaves the step.
   */
  static final String NOTE_BACKUP_CODES = "edc_enrol_backup_codes";

  /** Joins the codes into one note. They are digits only, so a comma cannot occur in one. */
  private static final String CODE_SEPARATOR = ",";

  static final String STEP_CHOOSE = "choose";
  static final String STEP_TELEGRAM = "telegram";
  static final String STEP_TOTP = "totp";
  static final String STEP_EMAIL = "email";
  static final String STEP_BACKUP = "backup";

  static final String FORM_CHANNEL = "channel";
  static final String FORM_CODE = "otp";
  static final String FORM_BACK = "back";

  private static final String TYPE_TOTP = "totp";
  private static final String TYPE_SPASS = "spass";
  private static final String TYPE_TAN = "tan";

  @Override
  public void evaluateTriggers(RequiredActionContext context) {
    // Nothing: enrolment is not triggered by Keycloak's own checks, it is put on the user by
    // edc-mfa-channels once it has established that the user has no working channel.
  }

  @Override
  public void requiredActionChallenge(RequiredActionContext context) {
    UserModel user = context.getUser();
    if (user == null) {
      context.success();
      return;
    }

    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String step = authSession == null ? null : authSession.getAuthNote(NOTE_STEP);

    if (step == null) {
      // The authoritative check, run once per login and only before the wizard has started.
      // Requiring a live channel as well as the marker is what makes clearing a user's channels send
      // them round again, instead of the stale marker waving them through.
      if (!EdcEnrolmentState.requiresEnrolment(context.getSession(), privacyIdea(context), user,
          authSession == null ? null : authSession.getClient())) {
        context.success();
        return;
      }
      step = startingStep(authSession, user, context);
      authSession.setAuthNote(NOTE_STEP, step);
    }

    try {
      render(context, authSession, step, null);
    } catch (Exception e) {
      // A privacyIDEA or bot failure must not dump the user on a stack trace. Back to the chooser,
      // where the failing channel is one of three they can route around.
      log.errorf(e, "method=requiredActionChallenge step=%s user=%s", step, user.getUsername());
      backToChooser(context, authSession, "edc.enrol.failed");
    }
  }

  @Override
  public void close() {
    // Nothing to release: every request builds its own privacyIDEA client.
  }

  @Override
  public void processAction(RequiredActionContext context) {
    UserModel user = context.getUser();
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    if (user == null || authSession == null) {
      context.success();
      return;
    }

    String step = authSession.getAuthNote(NOTE_STEP);
    MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();

    // "Choose a different method" is a step back, not a channel choice. Handled before the switch
    // so it works from any step.
    if (form.getFirst(FORM_BACK) != null) {
      clearWizard(authSession);
      render(context, authSession, STEP_CHOOSE, null);
      return;
    }

    try {
      switch (step == null ? STEP_CHOOSE : step) {
        case STEP_TELEGRAM -> finishTelegram(context, user, authSession);
        case STEP_TOTP -> verifyCode(context, user, authSession, EdcEnrolmentState.CHANNEL_TOTP);
        case STEP_EMAIL -> verifyCode(context, user, authSession, EdcEnrolmentState.CHANNEL_EMAIL);
        case STEP_BACKUP -> complete(context, user, authSession);
        default -> choose(context, user, authSession, form.getFirst(FORM_CHANNEL));
      }
    } catch (Exception e) {
      log.errorf(e, "method=processAction step=%s user=%s", step, user.getUsername());
      clearWizard(authSession);
      render(context, authSession, STEP_CHOOSE, "edc.enrol.failed");
    }
  }

  /**
   * Renders one step of the wizard.
   *
   * <p>Every rejection path lands here, rather than on {@code context.failure()}. Keycloak does not
   * re-invoke {@code requiredActionChallenge} after a POST: {@code processRequireAction} reads back
   * whatever {@code context.challenge(...)} was handed, and a {@code failure()} in that position
   * leaves it null and answers with an error page instead of the screen the user has to correct.
   * Keycloak's own required actions render their template again for the same reason.
   *
   * @param errorKey message to show above the step, or {@code null} for a clean render
   */
  private void render(RequiredActionContext context, AuthenticationSessionModel authSession,
      String step, String errorKey) {
    UserModel user = context.getUser();
    switch (step) {
      case STEP_TELEGRAM -> renderTelegram(context, errorKey);
      case STEP_TOTP -> renderCode(context, user, errorKey, EdcEnrolmentState.CHANNEL_TOTP);
      case STEP_EMAIL -> renderCode(context, user, errorKey, EdcEnrolmentState.CHANNEL_EMAIL);
      case STEP_BACKUP -> renderBackupCodes(context, user);
      default -> renderChoose(context, user, errorKey);
    }
  }

  /** Back to the start of the chooser, with a reason. */
  private void backToChooser(RequiredActionContext context, AuthenticationSessionModel authSession,
      String errorKey) {
    clearWizard(authSession);
    render(context, authSession, STEP_CHOOSE, errorKey);
  }

  // ------------------------------------------------------------------ steps

  /**
   * Where to start.
   *
   * <p>Someone who already has a working channel but never finished - linked Telegram last week,
   * marker never written - skips the chooser and goes straight to the codes they are missing.
   *
   * <p>Reads the notes {@code edc-mfa-channels} wrote rather than asking privacyIDEA again: if that
   * execution ran, the answer is already here, and if it did not, "offer the chooser" is always a
   * safe place to start.
   */
  private String startingStep(AuthenticationSessionModel authSession, UserModel user,
      RequiredActionContext context) {
    ClientModel client = authSession == null ? null : authSession.getClient();
    Map<String, String> current =
        EdcChannelDetector.detect(context.getSession(), privacyIdea(context), user, client);
    if (EdcChannelDetector.enrolmentRequired(context.getSession(), user, current, client)) {
      return STEP_CHOOSE;
    }
    boolean hasBackupCodes = "1".equals(current.get(EdcMfaChannelsAuthenticator.NOTE_BACKUP_CODE));
    return hasBackupCodes ? STEP_CHOOSE : STEP_BACKUP;
  }

  private void renderChoose(RequiredActionContext context, UserModel user, String errorKey) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    ClientModel client = authSession == null ? null : authSession.getClient();
    RealmModel realm = context.getRealm();

    boolean telegramPermitted = EdcChannelPolicy.isEnabled(client, realm, EdcChannelPolicy.TELEGRAM)
        && EdcChannelDetector.isTelegramConfigured(context.getSession());
    boolean emailPermitted = EdcChannelPolicy.isEnabled(client, realm, EdcChannelPolicy.EMAIL);
    boolean totpPermitted = EdcChannelPolicy.isEnabled(client, realm, EdcChannelPolicy.TOTP);

    Map<String, String> current =
        EdcChannelDetector.detect(context.getSession(), privacyIdea(context), user, client);
    boolean telegramConfigured = "1".equals(current.get(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM));
    boolean emailConfigured = "1".equals(current.get(EdcMfaChannelsAuthenticator.NOTE_EMAIL));
    boolean totpConfigured = "1".equals(current.get(EdcMfaChannelsAuthenticator.NOTE_TOTP));

    // The outstanding requirement, not the stored one. Every required channel has to be set up, but a
    // channel this person cannot reach is not held against them - and a "Required" badge beside a
    // row that is greyed out as Unavailable tells them to do something the server will then not
    // accept, so the two states have to come from the same rule the wizard itself obeys.
    Set<String> outstanding = EdcChannelDetector.pendingRequiredChannels(context.getSession(), user,
        current, EdcChannelPolicy.requiredFor(client, realm));

    LoginFormsProvider form = context.form();
    form.setAttribute("telegramAvailable", telegramPermitted);
    form.setAttribute("emailAvailable", emailPermitted);
    form.setAttribute("totpAvailable", totpPermitted);
    form.setAttribute("telegramConfigured", telegramConfigured);
    form.setAttribute("emailConfigured", emailConfigured);
    form.setAttribute("totpConfigured", totpConfigured);
    form.setAttribute("hasEmailAddress", EdcChannelDetector.hasEmailAddress(user));
    form.setAttribute("telegramRecommended", telegramPermitted && !telegramConfigured);
    form.setAttribute("error", errorKey);
    form.setAttribute("anyChannelAvailable", (telegramPermitted && !telegramConfigured)
        || (emailPermitted && !emailConfigured)
        || (totpPermitted && !totpConfigured));
    form.setAttribute("requiredChannels", outstanding.stream()
        .filter(java.util.List.of(EdcChannelPolicy.EMAIL, EdcChannelPolicy.TELEGRAM,
            EdcChannelPolicy.TOTP)::contains)
        .toList());
    context.challenge(form.createForm("edc-mfa-enrol-choose.ftl"));
  }

  private void choose(RequiredActionContext context, UserModel user,
      AuthenticationSessionModel authSession, String channel) throws Exception {
    if (channel == null) {
      render(context, authSession, STEP_CHOOSE, "edc.enrol.chooseError");
      return;
    }
    ClientModel client = authSession.getClient();
    if (!EdcChannelPolicy.isEnabled(client, context.getRealm(), channel)) {
      log.warnf("method=choose user=%s channel=%s status=REJECTED "
          + "message=Channel is switched off", user.getUsername(), channel);
      render(context, authSession, STEP_CHOOSE, "edc.enrol.chooseError");
      return;
    }
    Map<String, String> current =
        EdcChannelDetector.detect(context.getSession(), privacyIdea(context), user, client);
    boolean alreadyConfigured = switch (channel) {
      case EdcEnrolmentState.CHANNEL_TELEGRAM -> "1".equals(current.get(EdcMfaChannelsAuthenticator.NOTE_TELEGRAM));
      case EdcEnrolmentState.CHANNEL_EMAIL -> "1".equals(current.get(EdcMfaChannelsAuthenticator.NOTE_EMAIL));
      case EdcEnrolmentState.CHANNEL_TOTP -> "1".equals(current.get(EdcMfaChannelsAuthenticator.NOTE_TOTP));
      default -> false;
    };
    if (alreadyConfigured) {
      log.warnf("method=choose user=%s channel=%s status=ALREADY_CONFIGURED", user.getUsername(), channel);
      render(context, authSession, STEP_CHOOSE, "edc.enrol.alreadyConfigured");
      return;
    }
    switch (channel) {
      case EdcEnrolmentState.CHANNEL_TELEGRAM -> {
        // Same reasoning as the email branch: the row is only rendered when the bot is configured,
        // so this is unreachable except by a crafted POST - and a QR the bot cannot answer strands
        // the user at a screen that will never complete.
        if (!EdcChannelDetector.isTelegramConfigured(context.getSession())) {
          render(context, authSession, STEP_CHOOSE, "edc.enrol.telegramUnavailable");
          return;
        }
        authSession.setAuthNote(NOTE_STEP, STEP_TELEGRAM);
        renderTelegram(context, null);
      }
      case EdcEnrolmentState.CHANNEL_TOTP -> {
        enrolToken(context, user, authSession, TYPE_TOTP, settings(context).totpTokenParams());
        renderCode(context, user, null, EdcEnrolmentState.CHANNEL_TOTP);
      }
      case EdcEnrolmentState.CHANNEL_EMAIL -> {
        // Cannot normally happen - the row is disabled without an address - but a crafted POST gets
        // here, and enrolling a token nothing can be delivered to would strand the user behind a
        // channel that silently never arrives.
        if (!EdcChannelDetector.hasEmailAddress(user)) {
          render(context, authSession, STEP_CHOOSE, "edc.enrol.emailUnavailable");
          return;
        }
        enrolToken(context, user, authSession, TYPE_SPASS, Map.of());
        renderCode(context, user, null, EdcEnrolmentState.CHANNEL_EMAIL);
      }
      default -> render(context, authSession, STEP_CHOOSE, "edc.enrol.chooseError");
    }
  }

  private void renderTelegram(RequiredActionContext context, String errorKey) {
    String realmPath = "/realms/" + context.getRealm().getName();
    LoginFormsProvider form = context.form();
    form.setAttribute("telegramAlias", EdcChannelDetector.TELEGRAM_IDP_ALIAS);
    // The bot endpoints are reused as they are: they mint the deeplink and poll for the scan, and
    // both read the root authentication session this wizard is already running inside.
    form.setAttribute("telegramQrUrl", realmPath + "/telegram-auth/"
        + EdcChannelDetector.TELEGRAM_IDP_ALIAS + "/qr");
    form.setAttribute("telegramStatusUrl", realmPath + "/telegram-auth/status");
    form.setAttribute("telegramInitUrl", realmPath + "/telegram-auth/"
        + EdcChannelDetector.TELEGRAM_IDP_ALIAS + "/init");
    form.setAttribute("telegramPhoneUrl", realmPath + "/telegram-auth/"
        + EdcChannelDetector.TELEGRAM_IDP_ALIAS + "/phone-required");
    form.setAttribute("telegramLinkUrl", realmPath + "/privacyidea/enrolment/telegram-link");
    form.setAttribute("error", errorKey);
    context.challenge(form.createForm("edc-mfa-enrol-telegram.ftl"));
  }

  /**
   * The verify step, shared by the authenticator app and email.
   *
   * <p>Both enrol a token, both check the code the user typed against it with the same call, so the
   * only thing that differs is what is shown above the boxes.
   */
  private void renderCode(RequiredActionContext context, UserModel user, String errorKey,
      String channel) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    if (EdcEnrolmentState.CHANNEL_TOTP.equals(channel)
        && authSession.getAuthNote(NOTE_TOKEN_URI) == null) {
      // No URI means no QR and no token to check against - most likely the authentication session
      // was restarted. Repeat the step rather than render a page that cannot be completed.
      log.warnf("method=renderCode user=%s message=NoEnrolmentUri", user.getUsername());
      backToChooser(context, authSession, null);
      return;
    }
    LoginFormsProvider form = context.form();
    form.setAttribute("channel", channel);
    form.setAttribute("enrolmentUri", authSession.getAuthNote(NOTE_TOKEN_URI));
    form.setAttribute("emailMasked",
        EdcChannelDetector.maskEmail(user.getFirstAttribute("email")));
    form.setAttribute("codeLength", settings(context).backupCodeLength());
    form.setAttribute("error", errorKey);
    context.challenge(form.createForm("edc-mfa-enrol-code.ftl"));
  }

  private void renderBackupCodes(RequiredActionContext context, UserModel user) {
    AuthenticationSessionModel authSession = context.getAuthenticationSession();
    String stored = authSession.getAuthNote(NOTE_BACKUP_CODES);
    if (stored == null) {
      // Issue a fresh set rather than show a step with nothing on it. privacyIDEA keeps only hashes,
      // so there is no earlier set to recover - but issuing is exactly what the user needs anyway.
      //
      // This is every entry to the backup step that did not come from channelEnrolled, and the one
      // that matters is the wizard restarting: a user who has satisfied every required channel but
      // never finished comes back in with no session notes, startingStep sees the requirement met
      // and no backup codes, and lands here. It used to clear their enrolment and bounce them to
      // the chooser - where the only channel on offer was the one they had already set up, so
      // choosing it led straight back here. Marking the authenticator app required turns that into
      // a dead end for exactly the users it was meant to catch.
      log.infof("method=renderBackupCodes user=%s message=NoCodesInSession, issuing a new set",
          user.getUsername());
      try {
        issueBackupCodes(context, user, authSession, enrolledChannel(user));
      } catch (Exception e) {
        log.errorf(e, "method=renderBackupCodes user=%s message=Could not issue backup codes",
            user.getUsername());
        EdcEnrolmentState.clear(context.getSession(), user);
        backToChooser(context, authSession, "edc.enrol.failed");
      }
      return;
    }
    LoginFormsProvider form = context.form();
    form.setAttribute("backupCodes", List.of(stored.split(CODE_SEPARATOR)));
    context.challenge(form.createForm("edc-mfa-enrol-backup.ftl"));
  }

  /**
   * The channel to record against a backup-code issue that did not follow a channel step.
   *
   * <p>The record is only what a support call reads, so the marker from an earlier enrolment is the
   * honest answer, and "the backup codes" is the truth when there was never one.
   */
  private String enrolledChannel(UserModel user) {
    String recorded = user.getFirstAttribute(EdcEnrolmentState.ATTR_ENROLLED_CHANNEL);
    return recorded == null || recorded.isBlank() ? EdcEnrolmentState.CHANNEL_BACKUP_CODE : recorded;
  }

  // ------------------------------------------------------------------ work

  /** Enrols a privacyIDEA token for the channel a step is about to verify. */
  private void enrolToken(RequiredActionContext context, UserModel user,
      AuthenticationSessionModel authSession, String type, Map<String, String> params)
      throws Exception {
    PrivacyIdeaService pi = privacyIdea(context);
    String adminToken = pi.getPrivacyIdeaAuthToken();
    PrivacyIdeaService.InitialisedToken token =
        pi.initToken(user.getUsername(), type, adminToken, params);
    authSession.setAuthNote(NOTE_SERIAL, token.serial());

    if (TYPE_TOTP.equals(type)) {
      authSession.setAuthNote(NOTE_TOKEN_URI, token.googleUrl());
    } else {
      // The same delivery sign-in uses: write the PIN, then let the mail and the bot carry it.
      // Checking that code is what proves the address on file is one the user can actually read.
      EdcOtpDelivery.issue(context.getSession(), context.getRealm(), authSession.getClient(), user,
          settings(context), pi, adminToken, token.serial(), context.getConnection().getRemoteAddr());
    }
    authSession.setAuthNote(NOTE_STEP, TYPE_TOTP.equals(type) ? STEP_TOTP : STEP_EMAIL);
    log.infof("method=enrolToken user=%s type=%s serial=%s", user.getUsername(), type,
        token.serial());
  }

  private void finishTelegram(RequiredActionContext context, UserModel user,
      AuthenticationSessionModel authSession) throws Exception {
    // The page posts here once it has polled the bot and seen the scan confirmed. The federated
    // identity is written by the link endpoint, because that is where the AuthState proving the
    // scan lives.
    if (EdcChannelDetector.telegramChatId(context.getSession(), user) == null) {
      render(context, authSession, STEP_TELEGRAM, "edc.enrol.telegramNotLinked");
      return;
    }
    channelEnrolled(context, user, authSession, EdcEnrolmentState.CHANNEL_TELEGRAM);
  }

  /**
   * Checks the code the user typed, then completes the channel enrolment.
   *
   * <p>privacyIDEA is asked to check it against the user rather than against the serial enrolled a
   * moment ago: that is the same call the sign-in page makes, so the channel behaves identically
   * here and afterwards.
   */
  private void verifyCode(RequiredActionContext context, UserModel user,
      AuthenticationSessionModel authSession, String channel) throws Exception {
    PrivacyIdeaService pi = privacyIdea(context);
    String code = context.getHttpRequest().getDecodedFormParameters().getFirst(FORM_CODE);
    if (!pi.validateCheck(user.getUsername(), code, pi.getPrivacyIdeaAuthToken())) {
      render(context, authSession, EdcEnrolmentState.CHANNEL_TOTP.equals(channel) ? STEP_TOTP
          : STEP_EMAIL, "edc.enrol.codeRejected");
      return;
    }
    discardStepToken(authSession);
    channelEnrolled(context, user, authSession, channel);
  }

  /**
   * Called when one channel has been successfully verified during enrolment.
   *
   * <p>If more channels are required by policy (and the user is capable of configuring them),
   * returns the user to the chooser with a prompt to configure the next required channel.
   * Once all required channels are satisfied, issues backup codes as the final wizard step.
   */
  private void channelEnrolled(RequiredActionContext context, UserModel user,
      AuthenticationSessionModel authSession, String channel) throws Exception {
    ClientModel client = authSession.getClient();
    Map<String, String> current =
        EdcChannelDetector.detect(context.getSession(), privacyIdea(context), user, client);
    current.forEach(authSession::setAuthNote);

    boolean stillRequires =
        EdcChannelDetector.enrolmentRequired(context.getSession(), user, current, client);
    if (stillRequires) {
      log.infof("method=channelEnrolled user=%s channel=%s status=CHANNEL_COMPLETE_MORE_REQUIRED",
          user.getUsername(), channel);
      clearWizard(authSession);
      render(context, authSession, STEP_CHOOSE, "edc.enrol.channelSetupNextRequired");
      return;
    }

    issueBackupCodes(context, user, authSession, channel);
  }

  /**
   * Forgets the token serial and enrolment URI the finished step was holding.
   *
   * <p>The token itself stays: it has just proved itself, and it is the channel the user chose. What
   * has to go is the material that would let a later render show a QR for a token that is already
   * registered.
   */
  private void discardStepToken(AuthenticationSessionModel authSession) {
    authSession.removeAuthNote(NOTE_TOKEN_URI);
    authSession.removeAuthNote(NOTE_SERIAL);
  }

  /**
   * Issues the set of backup codes and shows it: the last thing the user sees.
   *
   * <p>Any earlier set is deleted first, so generating a new set stops the old codes working rather
   * than silently doubling what an attacker could try.
   */
  private void issueBackupCodes(RequiredActionContext context, UserModel user,
      AuthenticationSessionModel authSession, String channel) throws Exception {
    PrivacyIdeaService pi = privacyIdea(context);
    String adminToken = pi.getPrivacyIdeaAuthToken();

    pi.deleteTokens(user.getUsername(), TYPE_TAN, adminToken);
    PrivacyIdeaService.InitialisedToken token =
        pi.initToken(user.getUsername(), TYPE_TAN, adminToken, settings(context).backupCodeTokenParams());
    if (token.otps().isEmpty()) {
      // No codes means the TAN token would validate nothing. Carrying on would let someone finish
      // enrolment holding a second step they cannot use.
      throw new IllegalStateException("privacyIDEA issued no backup codes for " + user.getUsername());
    }

    authSession.setAuthNote(NOTE_BACKUP_CODES, String.join(CODE_SEPARATOR, token.otps()));
    authSession.setAuthNote(NOTE_CHANNEL, channel);
    authSession.setAuthNote(NOTE_STEP, STEP_BACKUP);
    renderBackupCodes(context, user);
  }

  private void complete(RequiredActionContext context, UserModel user,
      AuthenticationSessionModel authSession) {
    // The codes stay hashed in privacyIDEA, so there is nothing to persist and nothing that can
    // later be lost: they were in the page, and if the user wanted them, in their download.
    authSession.removeAuthNote(NOTE_BACKUP_CODES);
    EdcEnrolmentState.markComplete(context.getSession(), user,
          authSession.getAuthNote(NOTE_CHANNEL));
    clearWizard(authSession);
    log.infof("method=complete user=%s channel=%s", user.getUsername(),
        user.getFirstAttribute(EdcEnrolmentState.ATTR_ENROLLED_CHANNEL));
    context.success();
  }

  // ----------------------------------------------------------------- utils

  private PrivacyIdeaSettings.Settings settings(RequiredActionContext context) {
    return PrivacyIdeaSettings.resolve(context.getSession());
  }

  private PrivacyIdeaService privacyIdea(RequiredActionContext context) {
    PrivacyIdeaSettings.Settings settings = settings(context);
    return new PrivacyIdeaService(settings.baseUrlTrimmed(), settings.adminUsername(),
        settings.adminPassword());
  }

  private static boolean isOn(AuthenticationSessionModel authSession, String note) {
    return "1".equals(authSession.getAuthNote(note));
  }

  private static void clearWizard(AuthenticationSessionModel authSession) {
    authSession.removeAuthNote(NOTE_STEP);
    authSession.removeAuthNote(NOTE_CHANNEL);
    authSession.removeAuthNote(NOTE_SERIAL);
    authSession.removeAuthNote(NOTE_TOKEN_URI);
    authSession.removeAuthNote(NOTE_BACKUP_CODES);
  }
}
