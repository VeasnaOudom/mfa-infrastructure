package com.khalibre.keycloak.provider.edc;

import java.util.List;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Registers {@link EdcMfaAdminResource} at {@code /realms/{realm}/edc-mfa-admin/}.
 *
 * <p>Separate from the {@code privacyidea} provider that serves the challenge-cookie endpoints,
 * because it is a different audience with different authentication: those prove they hold an
 * issued challenge, this one proves the caller is ICT.
 */
public class EdcMfaAdminResourceFactory implements RealmResourceProviderFactory {

  public static final String PROVIDER_ID = "edc-mfa-admin";

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new EdcMfaAdminResource(session);
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
  public List<org.keycloak.provider.ProviderConfigProperty> getConfigMetadata() {
    // Deliberately empty: settings come from PrivacyIdeaSettings per request, so the admin console
    // and this endpoint cannot disagree about the privacyIDEA connection.
    return List.of();
  }
}
