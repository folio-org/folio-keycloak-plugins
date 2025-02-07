package org.folio.authentication;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

import java.util.Collections;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

class FolioEcsUsernamePasswordFormFactoryTest {

  private FolioEcsUsernamePasswordFormFactory factory;

  @BeforeEach
  void init() {
    factory = new FolioEcsUsernamePasswordFormFactory();
  }

  @Test
  void testCreate() {
    KeycloakSession session = mock(KeycloakSession.class);
    assertNotNull(factory.create(session));
  }

  @Test
  void testGetId() {
    assertEquals("ecs-folio-auth-usrnm-pwd-form", factory.getId());
  }

  @Test
  void testGetDisplayType() {
    assertEquals("ECS Folio Username Password Form", factory.getDisplayType());
  }

  @Test
  void testGetReferenceCategory() {
    assertEquals("password", factory.getReferenceCategory());
  }

  @Test
  void testIsConfigurable() {
    assertFalse(factory.isConfigurable());
  }

  @Test
  void testGetRequirementChoices() {
    Requirement[] requirements = factory.getRequirementChoices();
    assertArrayEquals(new Requirement[]{Requirement.REQUIRED}, requirements);
  }

  @Test
  void testIsUserSetupAllowed() {
    assertFalse(factory.isUserSetupAllowed());
  }

  @Test
  void testGetHelpText() {
    assertEquals("Validates a Folio username and password from login form in ECS setup.", factory.getHelpText());
  }

  @Test
  void testGetConfigProperties() {
    assertEquals(Collections.emptyList(), factory.getConfigProperties());
  }

  @Test
  void testInit() {
    assertDoesNotThrow(() -> factory.init(null));
  }

  @Test
  void testPostInit() {
    KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
    assertDoesNotThrow(() -> factory.postInit(sessionFactory));
  }

  @Test
  void testClose() {
    assertDoesNotThrow(factory::close);
  }
}
