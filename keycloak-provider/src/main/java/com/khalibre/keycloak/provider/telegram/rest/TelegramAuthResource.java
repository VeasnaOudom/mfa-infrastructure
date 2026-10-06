package com.khalibre.keycloak.provider.telegram.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.khalibre.keycloak.provider.telegram.state.AuthState;
import com.khalibre.keycloak.provider.telegram.state.AuthStateCache;
import com.khalibre.keycloak.provider.telegram.state.AuthStateSession;
import com.khalibre.keycloak.provider.telegram.bot.TelegramBotClient;
import com.khalibre.keycloak.provider.telegram.bot.TelegramBotManager;
import com.khalibre.keycloak.provider.telegram.bot.TelegramBotMode;
import com.khalibre.keycloak.provider.telegram.bot.TelegramUpdateHandler;
import com.khalibre.keycloak.provider.telegram.bot.TelegramWebhookPayload;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriInfo;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * JAX-RS resource exposed by the Telegram identity provider.
 *
 * <p>Generates a Telegram bot start deeplink URL for the configured bot.
 * The QR code is rendered client-side using qr-code-styling.
 *
 * <p>Endpoints (mounted at /realms/{realm}/telegram-auth/...):
 * <ul>
 *   <li>POST /{alias}/init - Initialize bot (start polling or set webhook)</li>
 *   <li>GET /{alias}/qr - QR code data (auth state ID + deeplink)</li>
 *   <li>POST /{alias}/webhook - Telegram update receiver (webhook mode)</li>
 * </ul>
 */
public class TelegramAuthResource implements RealmResourceProvider {

  private final KeycloakSession session;
  private final ObjectMapper objectMapper;

  @Context
  private UriInfo uriInfo;

  public TelegramAuthResource(KeycloakSession session) {
    this.session = session;
    this.objectMapper = new ObjectMapper();
  }

  @GET
  @Path("{alias}/qr")
  @Produces(MediaType.APPLICATION_JSON)
  public Response getQrCode(@PathParam("alias") String alias) {
    OAuth2IdentityProviderConfig config = getConfig(alias);
    if (config == null) {
      return Response.status(Response.Status.BAD_REQUEST)
        .entity(Map.of("error", "Telegram bot not configured",
          "alias", alias))
        .build();
    }

    String botUsername = config.getClientId();
    String botToken = config.getClientSecret();
    if (botUsername == null || botToken == null) {
      return Response.status(Response.Status.SERVICE_UNAVAILABLE)
        .entity(Map.of("error", "Telegram bot not configured"))
        .build();
    }

    AuthState oldAuthState = AuthStateSession.get(session, getAuthSessionId());
    if (oldAuthState != null && "EXPIRED".equalsIgnoreCase(oldAuthState.getStatus())) {
      LoginFormsProvider formProvider = session.getProvider(LoginFormsProvider.class);
      String message = formProvider.getMessage("telegram.session-expired");
      new TelegramBotClient(botToken).sendMessage(oldAuthState.getTelegramUserId(), message, null);
    }

    AuthState authState = AuthStateSession.create(session, getAuthSessionId());
    String deepLink = getDeepLink(botUsername, authState.getId());

    Map<String, Object> result = new HashMap<>();
    result.put("authStateId", authState.getId());
    result.put("deepLink", deepLink);
    result.put("botUsername", botUsername);

    return Response.ok(result).build();
  }

  private String getAuthSessionId() {
    RootAuthenticationSessionModel authSession = getAuthSession();
    if (authSession == null) {
      return null;
    }
    return authSession.getId();
  }

  private RootAuthenticationSessionModel getAuthSession() {
    AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
    return authSessionManager.getCurrentRootAuthenticationSession(session.getContext().getRealm());
  }

  private String getDeepLink(String botUsername, String authStateId) {
    return "https://t.me/" + botUsername + "?start=login_" + authStateId;
  }

  public OAuth2IdentityProviderConfig getConfig(String alias) {
    if (session == null || session.identityProviders() == null) {
      return null;
    }

    IdentityProviderModel idp = session.identityProviders().getByAlias(alias);
    if (idp == null) {
      return null;
    }
    return new OAuth2IdentityProviderConfig(idp);
  }

  @POST
  @Path("{alias}/init")
  @Produces(MediaType.APPLICATION_JSON)
  public Response initBot(@PathParam("alias") String alias) {
    OAuth2IdentityProviderConfig config = getConfig(alias);
    if (config == null) {
      return Response.status(Response.Status.BAD_REQUEST)
        .entity(Map.of("ok", false,
          "error", "Telegram bot not configured",
          "alias", alias))
        .build();
    }

    String botToken = config.getClientSecret();
    if (botToken == null) {
      return Response.status(Response.Status.SERVICE_UNAVAILABLE)
        .entity(Map.of("ok", false,
          "error", "Telegram bot not configured",
          "alias", alias))
        .build();
    }

    TelegramBotManager manager = TelegramBotManager.getInstance();

    if (manager.getMode() == TelegramBotMode.POLLING) {
      manager.startPolling(alias, botToken);
      return Response.ok(Map.of("ok", true,
          "mode", "polling",
          "alias", alias))
        .build();
    } else {
      String realmName = session.getContext().getRealm().getName();
      String webhookUrl = uriInfo.getBaseUriBuilder()
        .path("realms")
        .path(realmName)
        .path("telegram-auth")
        .path(alias)
        .path("webhook")
        .build()
        .toString();
      manager.setWebhook(alias, botToken, webhookUrl);
      return Response.ok(Map.of("ok", true,
          "mode", "webhook",
          "alias", alias,
          "webhookUrl", webhookUrl))
        .build();
    }
  }

  @POST
  @Path("{alias}/webhook")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public Response handleWebhook(@PathParam("alias") String alias, String payload) {
    try {
      OAuth2IdentityProviderConfig config = getConfig(alias);
      if (config == null) {
        return Response.status(Response.Status.BAD_REQUEST)
          .entity(Map.of("ok", false,
            "error", "Telegram bot not configured",
            "alias", alias))
          .build();
      }

      String botToken = config.getClientSecret();
      if (botToken == null) {
        return Response.status(Response.Status.SERVICE_UNAVAILABLE)
          .entity(Map.of("ok", false,
            "error", "Telegram bot not configured",
            "alias", alias))
          .build();
      }

      TelegramWebhookPayload update = objectMapper.readValue(payload,
        TelegramWebhookPayload.class);
      TelegramUpdateHandler handler = new TelegramUpdateHandler(botToken);
      handler.handleUpdate(update);

      return Response.ok(Map.of("ok", true)).build();
    } catch (Exception e) {
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
        .entity(Map.of("ok", false, "error", e.getMessage())).build();
    }
  }

  @GET
  @Path("status")
  @Produces(MediaType.APPLICATION_JSON)
  public Response getStatus() {
    AuthState state = AuthStateSession.get(session, getAuthSessionId());
    if (state == null) {
      return Response.status(Status.NOT_FOUND)
        .entity(Map.of("status", "EXPIRED"))
        .build();
    }

    Map<String, Object> result = new HashMap<>();
    result.put("status", state.getStatus());
    result.put("authStateId", state.getId());
    return Response.ok(result).build();
  }

  @GET
  @Path("{alias}/phone-required")
  @Produces(MediaType.APPLICATION_JSON)
  public Response isPhoneNumberRequired(@PathParam("alias") String alias) {
    OAuth2IdentityProviderConfig config = getConfig(alias);
    if (config == null) {
      return Response.status(Response.Status.BAD_REQUEST)
        .entity(Map.of("error", "Telegram bot not configured",
          "alias", alias))
        .build();
    }

    String botToken = config.getClientSecret();
    if (botToken == null) {
      return Response.status(Response.Status.SERVICE_UNAVAILABLE)
        .entity(Map.of("error", "Telegram bot not configured",
          "alias", alias))
        .build();
    }

    AuthState state = AuthStateSession.get(session, getAuthSessionId());
    if (state == null) {
      return Response.status(Status.NOT_FOUND)
        .entity(Map.of("status", "EXPIRED"))
        .build();
    }

    boolean accountLinked = isAccountLinked(alias, state);
    boolean phoneRequired = !accountLinked;
    if (!phoneRequired) {
      state.setStatus("COMPLETED");
      AuthStateCache.store(state.getId(), state);
    } else if (!state.isPhoneNumberRequested()) {
      String chatId = state.getTelegramUserId();
      if (chatId == null) {
        // The bot has not seen the /start command yet, so there is nobody to prompt. A 500 here
        // reads as "the server is broken" in the log and makes the enrolment page give up on
        // polling; "not yet" is the honest answer and the page will ask again.
        return Response.ok(Map.of("phoneRequired", false, "scanned", false)).build();
      }
      LoginFormsProvider formProvider = session.getProvider(LoginFormsProvider.class);
      String message = formProvider.getMessage("telegram.share-phone-number-prompt");
      String buttonText = formProvider.getMessage("telegram.share-phone-number-button");
      new TelegramBotClient(botToken).requestPhoneNumber(chatId, message, buttonText);
      state.setPhoneNumberRequested(true);
      AuthStateCache.store(state.getId(), state);
    }

    return Response.ok(Map.of("phoneRequired", phoneRequired, "scanned", true)).build();
  }

  private boolean isAccountLinked(String alias, AuthState state) {
    if (state.getTelegramUserId() == null) {
      return false;
    }

    RealmModel realm = session.getContext().getRealm();
    FederatedIdentityModel socialLink = new FederatedIdentityModel(
      alias,
      state.getTelegramUserId(),
      null
    );
    UserModel user = session.users().getUserByFederatedIdentity(realm, socialLink);
    return user != null;
  }

  @Override
  public Object getResource() {
    return this;
  }

  @Override
  public void close() {
    // No resources to close
  }
}