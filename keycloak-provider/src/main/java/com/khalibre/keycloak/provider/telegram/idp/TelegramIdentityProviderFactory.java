package com.khalibre.keycloak.provider.telegram.idp;

import com.khalibre.keycloak.provider.telegram.bot.TelegramBotManager;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class TelegramIdentityProviderFactory extends
  AbstractIdentityProviderFactory<TelegramIdentityProvider> {

  public static final String PROVIDER_ID = "telegram";
  public static final String AUTO_LINK_BY_PHONE_NUMBER_KEY = "autoLinkByPhoneNumber";

  @Override
  public String getName() {
    return "Telegram";
  }

  @Override
  public TelegramIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new TelegramIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
  }

  @Override
  public OAuth2IdentityProviderConfig createConfig() {
    return new OAuth2IdentityProviderConfig();
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
      .property()
      .name(AUTO_LINK_BY_PHONE_NUMBER_KEY)
      .label("Auto Link By Phone Number")
      .helpText(
        "Automatically link Telegram account to existing Keycloak user with matching phone number.")
      .type(ProviderConfigProperty.BOOLEAN_TYPE)
      .defaultValue("true")
      .add()
      .build();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public void init(Config.Scope config) {
    // no-op
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // Bot initialization is triggered via the /init endpoint, not at startup,
    // because identity providers may not be configured yet during postInit.
  }

  @Override
  public void close() {
    TelegramBotManager.getInstance().shutdown();
  }
}
