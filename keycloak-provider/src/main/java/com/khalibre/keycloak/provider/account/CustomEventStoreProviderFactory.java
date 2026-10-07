package com.khalibre.keycloak.provider.account;

import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventStoreProviderFactory;
import org.keycloak.events.jpa.JpaEventStoreProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomEventStoreProviderFactory implements EventStoreProviderFactory {

  @Override
  public EventStoreProvider create(KeycloakSession session) {
    JpaConnectionProvider connection = session.getProvider(JpaConnectionProvider.class);
    EventStoreProvider jpaEventStore = new JpaEventStoreProvider(session, connection.getEntityManager());
    return new CustomEventStoreProvider(jpaEventStore, new DeviceDetailService(session));
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

  @Override
  public String getId() {
    return "jpa";
  }

  @Override
  public int order() {
    return 100;
  }
}