package com.khalibre.keycloak.provider.privacyIdea;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class PrivacyIdeaWebhookResourceFactory implements RealmResourceProviderFactory {

  public static final String PROVIDER_ID = "privacyidea";

  /**
   * Settings come from {@link PrivacyIdeaSettings}, the same source the MFA channel detector uses,
   * so the webhook and the OTP page cannot disagree about the server or the shared secret. They are
   * resolved per request, so admin-console changes apply without a restart.
   */
  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    PrivacyIdeaSettings.Settings settings = PrivacyIdeaSettings.resolve(session);
    return new PrivacyIdeaWebhookResource(session, settings.baseUrlTrimmed(),
        settings.adminUsername(), settings.adminPassword(),
        Math.max(1, settings.spassExpiryMinutes()), settings.webhookSecret());
  }

  @Override
  public void init(Config.Scope config) {
    // Nothing cached here on purpose: values are read per request by create().
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
  }

  @Override
  public void close() {
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name("baseUrl")
        .label("privacyIDEA Base URL")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("http://mfa-privacyidea:8080")
        .helpText("Base URL of privacyIDEA server")
        .add()
        .property()
        .name("adminUsername")
        .label("Admin Username")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("admin")
        .helpText("Service account username to invoke REST APIs")
        .add()
        .property()
        .name("adminPassword")
        .label("Admin Password")
        .type(ProviderConfigProperty.PASSWORD)
        .helpText("Service account password")
        .add()
        .property()
        .name("spassExpiryMinutes")
        .label("SPASS Validity (Minutes)")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("5")
        .helpText("Expiry time in minutes for generated OTP PIN")
        .add()
        .property()
        .name("webhookSecret")
        .label("Webhook Shared Secret")
        .type(ProviderConfigProperty.PASSWORD)
        .helpText("Required as ?secret= on every webhook and resend call. Leave empty to disable the check.")
        .add()
        .build();
  }
}
