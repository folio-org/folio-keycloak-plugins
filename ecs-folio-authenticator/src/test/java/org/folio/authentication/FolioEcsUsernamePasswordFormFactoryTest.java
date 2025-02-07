package org.folio.authentication;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class FolioEcsUsernamePasswordFormFactoryTest {

  private FolioEcsUsernamePasswordFormFactory factory;

  @BeforeEach
  void init() {
    factory = new FolioEcsUsernamePasswordFormFactory();
  }

  @Test
  public void testCreate() {
    KeycloakSession session = mock(KeycloakSession.class);
    assertNotNull(factory.create(session));
  }

  @Test
  public void testGetId() {
    assertEquals("ecs-folio-auth-usrnm-pwd-form", factory.getId());
  }

  @Test
  public void testGetDisplayType() {
    assertEquals("ECS Folio Username Password Form", factory.getDisplayType());
  }

  @Test
  public void testGetReferenceCategory() {
    assertEquals("password", factory.getReferenceCategory());
  }

  @Test
  public void testIsConfigurable() {
    assertFalse(factory.isConfigurable());
  }

  @Test
  public void testGetRequirementChoices() {
    Requirement[] requirements = factory.getRequirementChoices();
    assertArrayEquals(new Requirement[]{Requirement.REQUIRED}, requirements);
  }

  @Test
  public void testIsUserSetupAllowed() {
    assertFalse(factory.isUserSetupAllowed());
  }

  @Test
  public void testGetHelpText() {
    assertEquals("Validates a Folio username and password from login form in ECS setup.", factory.getHelpText());
  }

  @Test
  public void testGetConfigProperties() {
    assertNull(factory.getConfigProperties());
  }

  @Test
  public void testInit() {
    assertDoesNotThrow(() -> factory.init(null));
  }

  @Test
  public void testPostInit() {
    KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
    assertDoesNotThrow(() -> factory.postInit(sessionFactory));
  }

  @Test
  public void testClose() {
    assertDoesNotThrow(factory::close);
  }
}
