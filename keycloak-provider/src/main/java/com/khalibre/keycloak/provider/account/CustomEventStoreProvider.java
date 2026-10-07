package com.khalibre.keycloak.provider.account;

import org.keycloak.events.Event;
import org.keycloak.events.EventQuery;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.AdminEventQuery;
import org.keycloak.models.RealmModel;

class CustomEventStoreProvider implements EventStoreProvider {

  private final EventStoreProvider jpaEventStore;
  private final DeviceDetailService deviceDetailService;

  CustomEventStoreProvider(EventStoreProvider jpaEventStore, DeviceDetailService deviceDetailService) {
    this.jpaEventStore = jpaEventStore;
    this.deviceDetailService = deviceDetailService;
  }

  @Override
  public EventQuery createQuery() {
    return jpaEventStore.createQuery();
  }

  @Override
  public AdminEventQuery createAdminQuery() {
    return jpaEventStore.createAdminQuery();
  }

  @Override
  public void clear() {
    jpaEventStore.clear();
  }

  @Override
  public void clear(RealmModel realm) {
    jpaEventStore.clear(realm);
  }

  @Override
  public void clear(RealmModel realm, long olderThan) {
    jpaEventStore.clear(realm, olderThan);
  }

  @Override
  public void clearExpiredEvents() {
    jpaEventStore.clearExpiredEvents();
  }

  @Override
  public void clearAdmin() {
    jpaEventStore.clearAdmin();
  }

  @Override
  public void clearAdmin(RealmModel realm) {
    jpaEventStore.clearAdmin(realm);
  }

  @Override
  public void clearAdmin(RealmModel realm, long olderThan) {
    jpaEventStore.clearAdmin(realm, olderThan);
  }

  @Override
  public void onEvent(Event event) {
    if (event != null) {
      event.setDetails(deviceDetailService.attachDeviceDetail(event));
    }
    jpaEventStore.onEvent(event);
  }

  @Override
  public void onEvent(AdminEvent event, boolean includeRepresentation) {
    jpaEventStore.onEvent(event, includeRepresentation);
  }

  @Override
  public void close() {
    jpaEventStore.close();
  }
}