package com.khalibre.keycloak.provider.util;

import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Lookups against a federated identity on the {@code telegram} identity provider.
 *
 * <p>Several places need to know whether a Telegram chat id is already bound to a Keycloak account,
 * and each was building its own {@code new FederatedIdentityModel(...)} and calling
 * {@code getUserByFederatedIdentity}. The model shape is trivial but the alias is the load-bearing
 * part: get it wrong and every lookup silently returns nothing. This is the single place that
 * pairs the two, so a rename of the identity provider cannot leave a stale alias behind.
 *
 * <p>The alias is a parameter rather than a constant because the Telegram identity provider is
 * referenced from multiple modules, and hardcoding its alias here would make this class the owner
 * of the truth it is supposed to centralise.
 */
public final class FederatedIdentity {

  private FederatedIdentity() {
  }

  /**
   * The user holding a federated identity for {@code tgUserId} under the identity provider
   * identified by {@code alias}.
   *
   * <p>The realm is taken from the session's context rather than passed in, because every caller
   * already has a session and the two would otherwise have to agree. A session with no realm
   * (a plain REST request, for example) resolves to {@code null} and the lookup answers
   * {@code null} rather than throwing.
   *
   * @return the owner, or {@code null} when no account claims this chat
   */
  public static UserModel getUserByTelegram(KeycloakSession session, String alias,
    String tgUserId) {
    if (session == null || alias == null || tgUserId == null || tgUserId.isBlank()) {
      return null;
    }
    RealmModel realm = session.getContext().getRealm();
    if (realm == null) {
      return null;
    }
    return session.users().getUserByFederatedIdentity(realm, federatedIdentity(alias, tgUserId));
  }

  /**
   * Whether any account holds a federated identity for {@code tgUserId} under the identity provider
   * identified by {@code alias}.
   *
   * <p>Convenience over {@link #getUserByTelegram} for the boolean callers, which were the
   * majority of the duplicated code.
   */
  public static boolean isTelegramLinked(KeycloakSession session, String alias, String tgUserId) {
    return getUserByTelegram(session, alias, tgUserId) != null;
  }

  private static FederatedIdentityModel federatedIdentity(String alias, String chatId) {
    return new FederatedIdentityModel(alias, chatId, null);
  }
}