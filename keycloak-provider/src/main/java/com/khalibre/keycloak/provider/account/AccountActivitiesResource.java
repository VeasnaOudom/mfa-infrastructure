package com.khalibre.keycloak.provider.account;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import org.keycloak.events.Event;
import org.keycloak.events.EventQuery;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Backs the "Account activities" page of the account console.
 *
 * <p>Mounted at <code>/realms/{realm}/account-activities/...</code> by
 * {@link AccountActivitiesResourceFactory}.
 *
 * <p>The endpoint only ever returns events of the caller: the user id comes from the verified
 * bearer token, never from a request parameter, so one user cannot read another user's activity
 * log. The token is required to be issued for the <code>account</code> client, which is what
 * the account console (client <code>account-console</code>) uses, and service accounts are
 * rejected. This mirrors the checks performed by Keycloak's own
 * {@code AccountRestService} so that a token which the account REST API would reject cannot
 * read the activity log either.
 */
public class AccountActivitiesResource implements RealmResourceProvider {

  /** Detail keys that are safe to render for the end user. */
  private static final Set<String> ALLOWED_DETAIL_KEYS =
      Set.of("auth_method", "identity_provider", "identity_provider_auth_method", "auth_method_details");

  private static final int DEFAULT_MAX_RESULTS = 25;
  private static final int MAX_ALLOWED_RESULTS = 100;

  /** Format accepted for the {@code dateFrom} filter, matching Keycloak's admin events API. */
  private static final String DATE_FORMAT = "yyyy-MM-dd";

  private final KeycloakSession session;

  public AccountActivitiesResource(KeycloakSession session) {
    this.session = session;
  }

  @GET
  @Path("events")
  @Produces(MediaType.APPLICATION_JSON)
  public Response getEvents(
      @QueryParam("first") Integer first,
      @QueryParam("max") Integer max,
      @QueryParam("type") List<String> types,
      @QueryParam("dateFrom") String dateFrom,
      @QueryParam("dateTo") String dateTo,
      @QueryParam("ipAddress") String ipAddress,
      @Context UriInfo uriInfo,
      @Context HttpHeaders headers) {
    RealmModel realm = session.getContext().getRealm();
    ClientModel accountClient = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
    if (accountClient == null || !accountClient.isEnabled()) {
      return Response.status(Response.Status.NOT_FOUND).build();
    }

    UserModel user = AccountConsoleCaller.resolve(session, uriInfo, headers);
    if (user == null) {
      throw new NotAuthorizedException("Bearer token required");
    }

    int firstResult = first == null ? 0 : Math.max(first, 0);
    int maxResults = max == null ? DEFAULT_MAX_RESULTS : Math.min(Math.max(max, 1), MAX_ALLOWED_RESULTS);
    Date fromDate = parseDate(dateFrom);
    Date toDate = parseDate(dateTo);
    EventType[] eventTypes = toEventTypes(types);

    EventStoreProvider store = session.getProvider(EventStoreProvider.class);
    List<AccountActivity> activities = new ArrayList<>();
    if (store != null) {
      EventQuery query =
          store
              .createQuery()
              .realm(realm.getId())
              .user(user.getId())
              .orderByDescTime()
              .firstResult(firstResult)
              .maxResults(maxResults);
      if (fromDate != null) {
        query = query.fromDate(fromDate);
      }
      if (toDate != null) {
        query = query.toDate(toDate);
      }
      if (eventTypes.length > 0) {
        query = query.type(eventTypes);
      }
      if (ipAddress != null && !ipAddress.isBlank()) {
        query = query.ipAddress(ipAddress.trim());
      }

      try (var events = query.getResultStream()) {
        events.map(this::toAccountActivity).forEach(activities::add);
      }
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("first", firstResult);
    result.put("max", maxResults);
    result.put("events", activities);
    return Response.ok(result).build();
  }

  /**
   * Parses a {@code yyyy-MM-dd} date filter into the start (UTC midnight) of that day.
   *
   * @return the parsed date, or {@code null} if {@code value} is blank or malformed.
   */
  private Date parseDate(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    SimpleDateFormat format = new SimpleDateFormat(DATE_FORMAT);
    format.setTimeZone(TimeZone.getTimeZone("UTC"));
    format.setLenient(false);
    try {
      return format.parse(value.trim());
    } catch (ParseException ignored) {
      return null;
    }
  }

  /** Converts the requested event type names into {@link EventType}s, skipping unknown names. */
  private EventType[] toEventTypes(List<String> types) {
    if (types == null || types.isEmpty()) {
      return new EventType[0];
    }
    List<EventType> parsed = new ArrayList<>();
    for (String type : types) {
      if (type == null || type.isBlank()) {
        continue;
      }
      try {
        parsed.add(EventType.valueOf(type.trim()));
      } catch (IllegalArgumentException ignored) {
        // Ignore unknown event types so a bad filter value cannot break the request.
      }
    }
    return parsed.toArray(new EventType[0]);
  }

  private AccountActivity toAccountActivity(Event event) {
    return new AccountActivity(
        event.getTime(),
        event.getType() == null ? EventType.LOGIN.name() : event.getType().name(),
        event.getClientId(),
        event.getIpAddress(),
        event.getError(),
        filterDetails(event.getDetails()));
  }

  private Map<String, String> filterDetails(Map<String, String> details) {
    if (details == null || details.isEmpty()) {
      return null;
    }

    Map<String, String> filtered = new LinkedHashMap<>();
    for (String key : ALLOWED_DETAIL_KEYS) {
      String value = details.get(key);
      if (value != null) {
        filtered.put(key, value);
      }
    }
    return filtered.isEmpty() ? null : filtered;
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {
    // Nothing to release.
  }
}
