package com.khalibre.keycloak.provider.edc;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers {@code edc-mfa-enrolled}, the condition that gates the second-factor subflow.
 *
 * <p>Keycloak 26 dropped the old {@code ConditionFactory} SPI: a conditional subflow is now an
 * ordinary subflow whose first execution is a {@code ConditionalAuthenticator}, and the flow engine
 * skips the subflow when that authenticator's {@code matchCondition} returns false. So this is
 * registered as an authenticator factory, in the same services file as the flow's other
 * executions.
 */
public class EdcMfaEnrolledConditionFactory
    implements org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory {

  public static final String PROVIDER_ID = "edc-mfa-enrolled";

  @Override
  public void init(Config.Scope config) {
  }

  @Override
  public EdcMfaEnrolledCondition getSingleton() {
    return EdcMfaEnrolledCondition.SINGLETON;
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
    return "Conditional - EDC MFA Enrolled";
  }

  @Override
  public String getReferenceCategory() {
    return null;
  }

  @Override
  public boolean isConfigurable() {
    return false;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return new Requirement[] { Requirement.REQUIRED };
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public List<org.keycloak.provider.ProviderConfigProperty> getConfigProperties() {
    return List.of();
  }

  @Override
  public String getHelpText() {
    return "Runs the second-step challenge only for users who have finished setting one up. "
        + "Put this as the first execution of the subflow holding the privacyIDEA authenticator: "
        + "while it does not match, the subflow is skipped and the user is sent to MFA enrolment.";
  }

  @Override
  public void close() {
  }
}
