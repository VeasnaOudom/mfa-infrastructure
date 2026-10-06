package com.khalibre.keycloak.provider.edc;

import com.khalibre.keycloak.provider.privacyIdea.PrivacyIdeaSettings;
import com.khalibre.keycloak.provider.privacyIdea.service.PrivacyIdeaService;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Registers the {@code edc-mfa-channels} execution used in the browser flow.
 *
 * The privacyIDEA service is built here rather than injected through a custom SPI, mirroring how
 * the webhook resource provider resolves its connection settings.
 */
public class EdcMfaChannelsAuthenticatorFactory
    implements org.keycloak.authentication.AuthenticatorFactory {

  public static final String PROVIDER_ID = "edc-mfa-channels";

  /**
   * Intentionally does not cache anything: {@link #create(KeycloakSession)} resolves the shared
   * settings on every login, so admin-console edits apply without a restart.
   */
  @Override
  public void init(Config.Scope config) {
  }

  /**
   * Resolves settings on every login rather than once at startup, so an operator changing them in
   * the admin console does not have to restart Keycloak for them to take effect.
   */
  @Override
  public EdcMfaChannelsAuthenticator create(KeycloakSession session) {
    PrivacyIdeaSettings.Settings settings = PrivacyIdeaSettings.resolve(session);
    return new EdcMfaChannelsAuthenticator(
        new PrivacyIdeaService(settings.baseUrlTrimmed(), settings.adminUsername(),
            settings.adminPassword()),
        settings.webhookSecret(),
        settings.challengeTtlSeconds());
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getDisplayType() {
    return "EDC MFA Channels";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return new Requirement[] { Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED };
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  /**
   * These are the canonical privacyIDEA settings for the realm: the webhook resource reads the
   * same values from here, so there is only ever one copy to edit.
   */
  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name(PrivacyIdeaSettings.KEY_BASE_URL)
        .label("privacyIDEA Base URL")
        .helpText("Base URL of the privacyIDEA server. Falls back to PRIVACYIDEA_URL.")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("http://mfa-privacyidea:8080")
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_ADMIN_USERNAME)
        .label("privacyIDEA Admin Username")
        .helpText("Service account used to read token state. Falls back to PI_ADMIN_USER.")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("admin")
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_ADMIN_PASSWORD)
        .label("privacyIDEA Admin Password")
        .helpText("Falls back to PI_ADMIN_PASSWORD.")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("secret")
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_WEBHOOK_SECRET)
        .label("Webhook Shared Secret")
        .helpText("Must match the secret in the privacyIDEA event handler URL, and signs the "
            + "browser challenge cookie. Falls back to PRIVACYIDEA_WEBHOOK_SECRET.")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("")
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_PUBLIC_BASE_URL)
        .label("Public Base URL")
        .helpText("Origin that links and images in outbound mail should point at. Needed because "
            + "Keycloak builds those from its own internal request address. Falls back to "
            + "KEYCLOAK_PUBLIC_BASE_URL, then https://KC_HOSTNAME.")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("")
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_EXPIRY_MINUTES)
        .label("OTP Expiry (minutes)")
        .helpText("Validity of a generated one-time code.")
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .defaultValue(5)
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_CHALLENGE_TTL_MINUTES)
        .label("Challenge Session (minutes)")
        .helpText("How long the OTP page may keep reading channels and sending a new code. "
            + "Keep this longer than the OTP expiry, otherwise the page goes dead as the code "
            + "expires. Falls back to PRIVACYIDEA_CHALLENGE_TTL_MINUTES.")
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .defaultValue(30)
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_BACKUP_CODE_COUNT)
        .label("Backup Codes per Set")
        .helpText("How many single-use codes are issued at the end of enrolment. Ten suits someone "
            + "who also has Telegram and an authenticator app; more suits someone who has no email "
            + "address to fall back on. Falls back to PRIVACYIDEA_BACKUP_CODE_COUNT.")
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .defaultValue(10)
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_BACKUP_CODE_LENGTH)
        .label("Backup Code Digits")
        .helpText("Digits per backup code. The sign-in code field is six boxes wide, so change this "
            + "only together with the field. privacyIDEA would otherwise default to eight. Falls "
            + "back to PRIVACYIDEA_BACKUP_CODE_LENGTH.")
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .defaultValue(6)
        .add()
        .property()
        .name(PrivacyIdeaSettings.KEY_ENROLMENT_GROUP)
        .label("Enrolled Users Group")
        .helpText("Group a user is added to when they finish enrolment, and removed from when their "
            + "MFA is reset. Name only, not a path, so a group at the top level of the realm is "
            + "matched by its name. Nothing here depends on it - the OTP gate reads the enrolment "
            + "marker, not the group - but it is where an operator looks for who has a second step "
            + "set up. Falls back to PRIVACYIDEA_ENROLMENT_GROUP, then MFA.")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("MFA")
        .add()
        .build();
  }

  @Override
  public String getHelpText() {
    return "Detects the MFA channels available to the user and exposes them to the OTP screen.";
  }

  @Override
  public void close() {
  }
}