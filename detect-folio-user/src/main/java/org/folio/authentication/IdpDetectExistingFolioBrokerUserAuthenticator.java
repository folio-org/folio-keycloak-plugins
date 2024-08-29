package org.folio.authentication;

import static org.folio.authentication.IdpDetectExistingFolioBrokerUserAuthenticatorFactory.EXTERNAL_ID_PROPERTY_DEFAULT_VALUE;
import static org.folio.authentication.IdpDetectExistingFolioBrokerUserAuthenticatorFactory.EXTERNAL_ID_PROPERTY_NAME;
import static org.keycloak.models.UserModel.EMAIL;
import static org.keycloak.models.UserModel.USERNAME;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.IdpDetectExistingBrokerUserAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.UserModel;

public class IdpDetectExistingFolioBrokerUserAuthenticator extends IdpDetectExistingBrokerUserAuthenticator {

  @Override
  protected ExistingUserInfo checkExistingUser(AuthenticationFlowContext context, String username,
    SerializedBrokeredIdentityContext serializedCtx, BrokeredIdentityContext brokerContext) {

    var externalIdAttrName = EXTERNAL_ID_PROPERTY_DEFAULT_VALUE;
    var config = context.getAuthenticatorConfig();
    if (config != null) {
      externalIdAttrName = config.getConfig().getOrDefault(EXTERNAL_ID_PROPERTY_NAME, externalIdAttrName);
    }
    if (brokerContext.getEmail() != null && !context.getRealm().isDuplicateEmailsAllowed()) {
      var matchingUsers = context.getSession().users()
        .searchForUserByUserAttributeStream(context.getRealm(), externalIdAttrName, brokerContext.getEmail()).toList();
      if (matchingUsers.size() == 1) {
        return toExistingUserInfo(matchingUsers.get(0), true);
      }
    }

    var matchingUsers =
      context.getSession().users().searchForUserByUserAttributeStream(context.getRealm(), externalIdAttrName, username)
        .toList();
    return matchingUsers.size() == 1 ? toExistingUserInfo(matchingUsers.get(0), false) : null;
  }

  private ExistingUserInfo toExistingUserInfo(UserModel user, boolean matchedByEmail) {
    return new ExistingUserInfo(user.getId(), matchedByEmail ? EMAIL : USERNAME,
      matchedByEmail ? user.getEmail() : user.getUsername());
  }
}
