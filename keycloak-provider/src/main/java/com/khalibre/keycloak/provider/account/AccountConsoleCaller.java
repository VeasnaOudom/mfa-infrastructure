package com.khalibre.keycloak.provider.account;

import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;

/**
 * Resolves the signed-in user behind a request from the account console.
 *
 * <p>Shared by every account-console-facing endpoint here so that they cannot drift apart on who is
 * allowed in. The checks mirror Keycloak's own {@code AccountRestService}:
 *
 * <ul>
 * <li>the token must be issued for the {@code account} client, which is what the console uses. A
 * token minted for some other audience is refused even if it is otherwise perfectly valid, so a token
 * obtained for an unrelated client cannot be replayed at these endpoints.
 * <li>service accounts are refused. A service account has no human behind it and no reason to read
 * or change a user's own MFA setup.
 * </ul>
 *
 * <p>Note the deliberate absence of any role check. The account console presents an ordinary
 * end-user token, which on this realm carries no role claims at all, and the account client needs
 * none for the console to work. Authorization here is "this is you", never "this is an
 * administrator".
 */
public final class AccountConsoleCaller {

  private AccountConsoleCaller() {
  }

  /**
   * Verifies the bearer token and resolves the user it belongs to.
   *
   * @return the authenticated user, or {@code null} if the token is missing, not valid, not issued
   *     for the account client, or belongs to a service account
   */
  public static UserModel resolve(KeycloakSession session, UriInfo uriInfo, HttpHeaders headers) {
    RealmModel realm = session.getContext().getRealm();
    ClientModel accountClient = realm.getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
    if (accountClient == null || !accountClient.isEnabled()) {
      return null;
    }

    String tokenString = AppAuthManager.extractAuthorizationHeaderTokenOrReturnNull(headers);
    if (tokenString == null) {
      return null;
    }

    AuthenticationManager.AuthResult authResult =
        new AppAuthManager.BearerTokenAuthenticator(session)
            .setUriInfo(uriInfo)
            .setHeaders(headers)
            .setConnection(session.getContext().getConnection())
            .setTokenString(tokenString)
            .authenticate();

    if (authResult == null || authResult.getUser() == null) {
      return null;
    }

    AccessToken accessToken = authResult.getToken();
    if (accessToken == null || !accessToken.hasAudience(accountClient.getClientId())) {
      return null;
    }

    if (authResult.getUser().getServiceAccountClientLink() != null) {
      return null;
    }

    return authResult.getUser();
  }
}