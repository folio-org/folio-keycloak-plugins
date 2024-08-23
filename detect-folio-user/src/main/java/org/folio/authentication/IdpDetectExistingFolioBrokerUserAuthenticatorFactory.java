package org.folio.authentication;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class IdpDetectExistingFolioBrokerUserAuthenticatorFactory implements AuthenticatorFactory {
  public static final String EXTERNAL_ID_PROPERTY_NAME = "externalIdAttributeName";
  public static final String PROVIDER_ID = "idp-detect-folio-broker-user";
  private static final IdpDetectExistingFolioBrokerUserAuthenticator SINGLETON =
    new IdpDetectExistingFolioBrokerUserAuthenticator();

  @Override
  public Authenticator create(KeycloakSession session) {
    return SINGLETON;
  }

  @Override
  public void init(Config.Scope config) {}

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  @Override
  public String getReferenceCategory() {
    return "detectExistingFOLIOBrokerUser";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
    return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED,
      AuthenticationExecutionModel.Requirement.DISABLED};
  }

  @Override
  public String getDisplayType() {
    return "Detect existing FOLIO broker user";
  }

  @Override
  public String getHelpText() {
    return "Detect if there is an existing Keycloak account with same externalId attribute like identity provider. If no, throw an error.";
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    var customProperty = new ProviderConfigProperty();
    customProperty.setName(EXTERNAL_ID_PROPERTY_NAME);
    customProperty.setLabel("User attribute containing external ID");
    customProperty.setType(ProviderConfigProperty.STRING_TYPE);
    customProperty.setHelpText("The external ID attribute of a user profile should contain an email or a "
      + "username by which Keycloak user will be matched with the external user");

    return List.of(customProperty);
  }
}
