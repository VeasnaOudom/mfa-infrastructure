package com.khalibre.keycloak.provider.telegram.idp;

import static com.khalibre.keycloak.provider.telegram.idp.TelegramIdentityProviderFactory.AUTO_LINK_BY_PHONE_NUMBER_KEY;

import com.khalibre.keycloak.provider.telegram.bot.TelegramBotClient;
import com.khalibre.keycloak.provider.telegram.state.AuthState;
import com.khalibre.keycloak.provider.telegram.state.AuthStateSession;
import com.khalibre.keycloak.provider.edc.EdcChannelDetector;
import org.jboss.logging.Logger;

import jakarta.annotation.Nonnull;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;
import java.net.URI;
import java.util.Iterator;
import java.util.stream.Stream;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

public class TelegramIdentityProvider extends
  AbstractIdentityProvider<OAuth2IdentityProviderConfig> {

  private static final Logger log = Logger.getLogger(TelegramIdentityProvider.class);

  /**
   * Attribute names live on {@link EdcChannelDetector}, which is also how MFA enrolment links a
   * Telegram account. Kept in one place because the channel detector has to read back what is
   * written here, and two copies of an attribute name would fail quietly: the write would succeed
   * and the channel would never appear.
   */
  private static final String ATTR_TG_FIRST_NAME = EdcChannelDetector.TELEGRAM_FIRST_NAME_ATTR;
  private static final String ATTR_TG_LAST_NAME = EdcChannelDetector.TELEGRAM_LAST_NAME_ATTR;
  private static final String ATTR_TG_USERNAME = EdcChannelDetector.TELEGRAM_USERNAME_ATTR;
  private static final String ATTR_TG_USER_ID = EdcChannelDetector.TELEGRAM_USER_ID_ATTR;
  private static final String ATTR_TG_USER_PHONE_NUMBER = "telegram-phone-number";
  private static final String ATTR_TG_REQUIRE_PHONE_MATCH = "telegram-require-phone-match";

  public TelegramIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
    super(session, config);
  }

  private boolean isAutoLinkByPhoneNumberEnabled() {
    String value = getConfig().getConfig().get(AUTO_LINK_BY_PHONE_NUMBER_KEY);
    return "true".equalsIgnoreCase(value);
  }

  public String getBotUsername() {
    return getConfig().getClientId();
  }

  public String getBotToken() {
    return getConfig().getClientSecret();
  }

  @Override
  public Response retrieveToken(KeycloakSession keycloakSession,
    FederatedIdentityModel federatedIdentityModel) {
    return null;
  }

  @Override
  public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm,
    BrokeredIdentityContext context) {
  }

  @Override
  public void authenticationFinished(AuthenticationSessionModel authSession,
    BrokeredIdentityContext context) {
  }

  @Override
  public void importNewUser(KeycloakSession session, RealmModel realm, UserModel user,
    BrokeredIdentityContext context) {
    user.setSingleAttribute(ATTR_TG_USER_ID, context.getUserAttribute(ATTR_TG_USER_ID));
    user.setSingleAttribute(ATTR_TG_USERNAME, context.getUserAttribute(ATTR_TG_USERNAME));
    user.setSingleAttribute(ATTR_TG_USER_PHONE_NUMBER,
      context.getUserAttribute(ATTR_TG_USER_PHONE_NUMBER));
    user.setSingleAttribute(ATTR_TG_FIRST_NAME, context.getUserAttribute(ATTR_TG_FIRST_NAME));
    user.setSingleAttribute(ATTR_TG_LAST_NAME, context.getUserAttribute(ATTR_TG_LAST_NAME));
  }

  @Override
  public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user,
    BrokeredIdentityContext context) {
    user.setSingleAttribute(ATTR_TG_USER_ID, context.getUserAttribute(ATTR_TG_USER_ID));
    user.setSingleAttribute(ATTR_TG_USERNAME, context.getUserAttribute(ATTR_TG_USERNAME));
    user.setSingleAttribute(ATTR_TG_USER_PHONE_NUMBER,
      context.getUserAttribute(ATTR_TG_USER_PHONE_NUMBER));
    user.setSingleAttribute(ATTR_TG_FIRST_NAME, context.getUserAttribute(ATTR_TG_FIRST_NAME));
    user.setSingleAttribute(ATTR_TG_LAST_NAME, context.getUserAttribute(ATTR_TG_LAST_NAME));
  }

  @Override
  public void backchannelLogout(KeycloakSession session, UserSessionModel userSession,
    UriInfo uriInfo, RealmModel realm) {
  }

  @Override
  public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
    UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
    return null;
  }

  @Override
  public Response export(UriInfo uriInfo, RealmModel realm, String subject) {
    return null;
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new Endpoint(callback, event, session, this);
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {
    try {
      final UriBuilder uriBuilder = UriBuilder.fromUri(request.getRedirectUri());
      uriBuilder.queryParam("state", request.getState().getEncoded());
      URI callbackUrl = uriBuilder.build();
      return renderPage(request, callbackUrl);
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not create authentication request.", e);
    }
  }

  private Response renderPage(AuthenticationRequest request, URI callbackUrl) {
    LoginFormsProvider formProvider = session.getProvider(LoginFormsProvider.class);
    formProvider.setAuthenticationSession(request.getAuthenticationSession());
    UserModel user = request.getAuthenticationSession().getAuthenticatedUser();
    if (user != null) {
      formProvider.setUser(user);
    }
    boolean isLinkMode =
      request.getAuthenticationSession().getAuthNote("LINKING_IDENTITY_PROVIDER") != null;
    formProvider.setAttribute("linkMode", isLinkMode);
    formProvider.setAttribute("callbackUrl", callbackUrl.toString());
    formProvider.setAttribute("providerAlias", getConfig().getAlias());
    return formProvider.createForm("telegram-qr-link.ftl");
  }

  private static String sanitizeEmojiAndRareScript(String input) {
    if (StringUtil.isBlank(input)) {
      return input;
    }
    return input.replaceAll("[^\\u0000-\\uFFFF]", "");
  }

  private static class Endpoint {

    private final AuthenticationCallback callback;
    private final EventBuilder event;
    private final KeycloakSession session;
    private final TelegramIdentityProvider provider;

    private Endpoint(AuthenticationCallback callback, EventBuilder event, KeycloakSession session,
      TelegramIdentityProvider self) {
      this.callback = callback;
      this.event = event;
      this.session = session;
      this.provider = self;
    }

    @GET
    @Path("/")
    public Response authenticate(@QueryParam("state") String state) {
      try {
        AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(state);
        session.getContext().setAuthenticationSession(authSession);
        String sessionId = authSession.getParentSession().getId();

        AuthState auth = AuthStateSession.get(session, sessionId);
        if (auth == null || !"COMPLETED".equals(auth.getStatus())) {
          return telegramRejected(sessionId, auth, "telegram.session-expired");
        }

        boolean isLinkMode = authSession.getAuthNote("LINKING_IDENTITY_PROVIDER") != null;

        String autoLinkUsername;
        if (isLinkMode) {
          UserModel authenticatedUser = findAuthenticatedUser(authSession);
          if (authenticatedUser == null
            || (isPhoneMatchRequired(authenticatedUser)
            && !isPhoneMatched(authenticatedUser, auth.getPhoneNumber()))) {
            return telegramRejected(sessionId, auth, "telegram.link-phone-mismatch");
          }
          // One Telegram account belongs to one person. Without this, scanning the same phone from a
          // second account links it too, and both accounts then receive codes at the same chat.
          UserModel otherHolder = EdcChannelDetector.anotherUserHolding(session,
            session.getContext().getRealm(), authenticatedUser, auth.getTelegramUserId());
          if (otherHolder != null) {
            log.warnf("method=authenticate chat=%s targetUser=%s alreadyHeldBy=%s "
                + "message=TelegramAlreadyLinked",
                auth.getTelegramUserId(), authenticatedUser.getUsername(),
                otherHolder.getUsername());
            return telegramRejected(sessionId, auth, "telegram.link-already-linked");
          }
          autoLinkUsername = authenticatedUser.getUsername();
        } else {
          autoLinkUsername = findAutoLinkUsername(auth.getPhoneNumber());
        }

        AuthStateSession.remove(session, sessionId);

        boolean accountLinked = isAccountLinked(provider.getConfig().getAlias(), auth);
        if (accountLinked || autoLinkUsername != null) {
          sendToTelegram(auth, isLinkMode ? "telegram.link-success" : "telegram.login-success");
        } else {
          return telegramRejected(sessionId, auth, isLinkMode ? "telegram.link-failed" : "telegram.login-failed");
        }

        BrokeredIdentityContext context = buildContext(
          auth.getTelegramUserId(),
          autoLinkUsername,
          auth.getUsername(),
          auth.getFirstName(),
          auth.getLastName(),
          auth.getPhoneNumber(),
          authSession);
        return callback.authenticated(context);
      } catch (WebApplicationException wae) {
        throw wae;
      } catch (Exception e) {
        return errorIdentityProviderLogin(e.getMessage());
      }
    }

    private void sendToTelegram(AuthState auth, String messageKey) {
      if (auth == null) {
        return;
      }
      String tgUserId = auth.getTelegramUserId();
      String botToken = provider.getBotToken();
      if (tgUserId != null && botToken != null) {
        LoginFormsProvider formProvider = session.getProvider(LoginFormsProvider.class);
        String message = formProvider.getMessage(messageKey);
        new TelegramBotClient(botToken).sendMessage(tgUserId, message, null);
      }
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

    private UserModel findAuthenticatedUser(AuthenticationSessionModel authSession) {
      UserModel user = authSession.getAuthenticatedUser();
      if (user != null) {
        return user;
      }

      UserSessionModel userSession = session.getContext().getUserSession();
      if (userSession == null) {
        RootAuthenticationSessionModel rootSession = authSession.getParentSession();
        if (rootSession != null) {
          RealmModel realm = session.getContext().getRealm();
          userSession = session.sessions().getUserSession(realm, rootSession.getId());
        }
      }
      return userSession != null ? userSession.getUser() : null;
    }

    private String findAutoLinkUsername(String phoneNumber) {
      if (!provider.isAutoLinkByPhoneNumberEnabled()) {
        return null;
      }

      UserModel user = findUserByPhoneNumber(phoneNumber);
      return user != null ? user.getUsername() : null;
    }

    private UserModel findUserByPhoneNumber(String phoneNumber) {
      if (StringUtil.isBlank(phoneNumber)) {
        return null;
      }

      RealmModel realm = session.getContext().getRealm();
      try (Stream<UserModel> matches = provider.session.users()
        .searchForUserByUserAttributeStream(realm, ATTR_TG_USER_PHONE_NUMBER, phoneNumber)) {
        Iterator<UserModel> iterator = matches.iterator();
        if (!iterator.hasNext()) {
          return null;
        }

        UserModel user = iterator.next();
        if (iterator.hasNext()) {
          return null;
        }

        String providerAlias = provider.getConfig().getAlias();
        if (provider.session.users().getFederatedIdentity(realm, user, providerAlias) != null) {
          return null;
        }
        return user;
      }
    }

    @Nonnull
    private BrokeredIdentityContext buildContext(String tgUserId, String autoLinkUsername,
      String username, String firstName, String lastName, String phoneNumber,
      AuthenticationSessionModel authSession) {
      BrokeredIdentityContext context = new BrokeredIdentityContext(tgUserId, provider.getConfig());
      if (autoLinkUsername != null) {
        context.setModelUsername(autoLinkUsername);
      } else {
        context.setModelUsername(phoneNumber);
      }
      context.setUsername(username);
      context.setFirstName(sanitizeEmojiAndRareScript(firstName));
      context.setLastName(sanitizeEmojiAndRareScript(lastName));

      context.setUserAttribute(ATTR_TG_USER_ID, tgUserId);
      context.setUserAttribute(ATTR_TG_USERNAME, username);
      context.setUserAttribute(ATTR_TG_USER_PHONE_NUMBER, phoneNumber);
      context.setUserAttribute(ATTR_TG_FIRST_NAME, firstName);
      context.setUserAttribute(ATTR_TG_LAST_NAME, lastName);

      context.setIdp(provider);
      context.setAuthenticationSession(authSession);
      return context;
    }

    private boolean isPhoneMatchRequired(UserModel user) {
      String value = user.getFirstAttribute(ATTR_TG_REQUIRE_PHONE_MATCH);
      return !StringUtil.isBlank(value) && value.equalsIgnoreCase("true");
    }

    private boolean isPhoneMatched(UserModel authenticatedUser, String phoneNumber) {
      if (StringUtil.isBlank(phoneNumber)) {
        return false;
      }

      String userPhoneNumber = authenticatedUser.getFirstAttribute(ATTR_TG_USER_PHONE_NUMBER);
      if (StringUtil.isBlank(userPhoneNumber)) {
        return true;
      }

      if (phoneNumber.equals(userPhoneNumber)) {
        return true;
      }

      UserModel matchedUser = findUserByPhoneNumber(phoneNumber);
      return matchedUser != null && matchedUser.getId().equals(authenticatedUser.getId());
    }

    /** Refuse the scan, say why in the Telegram chat, and show the user an error. */
    private Response telegramRejected(String sessionId, AuthState auth, String message) {
      AuthStateSession.remove(session, sessionId);
      sendToTelegram(auth, message);
      event.event(EventType.IDENTITY_PROVIDER_LOGIN);
      event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
      return ErrorPage.error(session, null, Status.BAD_REQUEST, message);
    }

    private Response errorIdentityProviderLogin(String message) {
      try {
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession != null) {
          String sessionId = authSession.getParentSession().getId();
          AuthState auth = AuthStateSession.get(session, sessionId);
          if (auth != null && auth.getTelegramUserId() != null) {
            String botToken = provider.getBotToken();
            if (botToken != null) {
              boolean isLinkMode = authSession.getAuthNote("LINKING_IDENTITY_PROVIDER") != null;
              String errorKey = isLinkMode ? "telegram.link-failed" : "telegram.login-failed";
              sendToTelegram(auth, errorKey);
            }
          }
        }
      } catch (Exception ignored) {
        // Best effort - don't fail the error response if Telegram notification fails
      }

      event.event(EventType.IDENTITY_PROVIDER_LOGIN);
      event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
      return ErrorPage.error(session, null, Status.BAD_REQUEST, message);
    }
  }
}