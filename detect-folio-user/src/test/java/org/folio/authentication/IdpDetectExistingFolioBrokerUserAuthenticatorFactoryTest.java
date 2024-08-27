package org.folio.authentication;

import static org.folio.authentication.IdpDetectExistingFolioBrokerUserAuthenticatorFactory.EXTERNAL_ID_PROPERTY_NAME;
import static org.folio.authentication.IdpDetectExistingFolioBrokerUserAuthenticatorFactory.PROVIDER_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.DISABLED;
import static org.keycloak.models.AuthenticationExecutionModel.Requirement.REQUIRED;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IdpDetectExistingFolioBrokerUserAuthenticatorFactoryTest {

  private IdpDetectExistingFolioBrokerUserAuthenticatorFactory unit;

  @BeforeEach
  void init() {
    unit = new IdpDetectExistingFolioBrokerUserAuthenticatorFactory();
  }

  @Test
  void verifyIdentifiersAndDescriptions() {
    assertEquals(PROVIDER_ID, unit.getId());
    assertEquals("Detect existing FOLIO broker user", unit.getDisplayType());
    assertEquals("Detect if there is an existing Keycloak account "
      + "with same externalId attribute like identity provider. If no, throw an error.", unit.getHelpText());
    assertEquals("detectExistingFOLIOBrokerUser", unit.getReferenceCategory());
    assertFalse(unit.isUserSetupAllowed());
    assertEquals(2, unit.getRequirementChoices().length);
    assertEquals(REQUIRED, unit.getRequirementChoices()[0]);
    assertEquals(DISABLED, unit.getRequirementChoices()[1]);
  }

  @Test
  void testCreate() {
    unit.init(mock(Config.Scope.class));
    unit.postInit(mock(KeycloakSessionFactory.class));
    assertNotNull(unit.create(mock(KeycloakSession.class)));
    unit.close();
  }

  @Test
  void verifyConfigParams() {
    assertTrue(unit.isConfigurable());
    var configProps = unit.getConfigProperties();
    assertEquals(1, configProps.size());
    assertEquals(EXTERNAL_ID_PROPERTY_NAME, configProps.get(0).getName());
    assertEquals(STRING_TYPE, configProps.get(0).getType());
  }
}
