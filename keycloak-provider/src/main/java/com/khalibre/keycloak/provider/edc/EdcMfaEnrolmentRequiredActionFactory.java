package com.khalibre.keycloak.provider.edc;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers {@code edc-mfa-enrolment}, the required action that makes a second step mandatory.
 *
 * <p>Appears in the realm's list of required actions as <em>EDC MFA Enrolment</em>, but is not meant
 * to be added to the realm's default set: {@code edc-mfa-channels} puts it on individual users, and
 * only for as long as they have no working channel. Adding it to the defaults would send everyone
 * through the wizard on every sign-in.
 */
public class EdcMfaEnrolmentRequiredActionFactory
    implements org.keycloak.authentication.RequiredActionFactory {

  public static final String PROVIDER_ID = EdcMfaEnrolmentRequiredAction.PROVIDER_ID;

  @Override
  public EdcMfaEnrolmentRequiredAction create(KeycloakSession session) {
    return new EdcMfaEnrolmentRequiredAction();
  }

  @Override
  public void init(Config.Scope config) {
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
  public String getDisplayText() {
    return "EDC MFA Enrolment";
  }
}
