package org.folio.authentication;

import static org.keycloak.models.UserModel.EMAIL;
import static org.keycloak.models.UserModel.USERNAME;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.IdpDetectExistingBrokerUserAuthenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

public class IdpDetectExistingFolioBrokerUserAuthenticator extends IdpDetectExistingBrokerUserAuthenticator {
  public static final String EXTERNAL_ID_PROPERTY_NAME = "externalIdAttributeName";
  public static final String EXTERNAL_ID_PROPERTY_DEFAULT_VALUE = "externalId";

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

  protected static ProviderConfigProperty getProviderConfigProperty() {
    var customProperty = new ProviderConfigProperty();
    customProperty.setName(EXTERNAL_ID_PROPERTY_NAME);
    customProperty.setLabel("User attribute containing external ID");
    customProperty.setType(STRING_TYPE);
    customProperty.setHelpText("The external ID attribute of a user profile should contain an email or a "
      + "username by which Keycloak user will be matched with the external user");
    customProperty.setDefaultValue(EXTERNAL_ID_PROPERTY_DEFAULT_VALUE);

    return customProperty;
  }
}
