package com.khalibre.keycloak.provider.telegram.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory that registers the TelegramAuthResource REST endpoint under
 * /realms/{realm}/telegram-auth/...
 */
public class TelegramAuthResourceFactory implements RealmResourceProviderFactory {

  public static final String PROVIDER_ID = "telegram-auth";

  @Override
  public TelegramAuthResource create(KeycloakSession session) {
    return new TelegramAuthResource(session);
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
    // no-op
  }

  @Override
  public void close() {
    // no-op
  }
}