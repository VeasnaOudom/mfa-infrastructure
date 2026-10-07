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
   * The user holding a federated identity for {@code chatId} under the identity provider
   * identified by {@code alias}.
   *
   * @return the owner, or {@code null} when no account claims this chat
   */
  public static UserModel getUserByTelegramChat(KeycloakSession session, RealmModel realm,
    String alias, String chatId) {
    if (session == null || realm == null || alias == null || chatId == null || chatId.isBlank()) {
      return null;
    }
    return session.users()
      .getUserByFederatedIdentity(realm, federatedIdentity(alias, chatId));
  }

  /**
   * Whether any account holds a federated identity for {@code chatId} under the identity provider
   * identified by {@code alias}.
   *
   * <p>Convenience over {@link #getUserByTelegramChat} for the boolean callers, which were the
   * majority of the duplicated code.
   */
  public static boolean isTelegramChatLinked(KeycloakSession session, RealmModel realm,
    String alias, String chatId) {
    return getUserByTelegramChat(session, realm, alias, chatId) != null;
  }

  private static FederatedIdentityModel federatedIdentity(String alias, String chatId) {
    return new FederatedIdentityModel(alias, chatId, null);
  }
}