package com.khalibre.keycloak.provider.edc;

import java.util.List;

import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Registers {@link EdcMfaSettingsResource} at {@code /realms/{realm}/edc-mfa-settings/}.
 *
 * <p>Its own mount rather than a path under the {@code privacyidea} provider, because the audience
 * is different: those endpoints prove the caller holds a signed challenge cookie issued during
 * sign-in, this one proves the caller is a signed-in account-console user and acts on their own
 * account only.
 */
public class EdcMfaSettingsResourceFactory implements RealmResourceProviderFactory {

  public static final String PROVIDER_ID = "edc-mfa-settings";

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new EdcMfaSettingsResource(session);
  }

  @Override
  public void init(org.keycloak.Config.Scope config) {
  }

  @Override
  public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
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
    // Deliberately empty: settings resolve per request from PrivacyIdeaSettings, so the admin console
    // and these endpoints cannot disagree about the privacyIDEA connection.
    return List.of();
  }
}