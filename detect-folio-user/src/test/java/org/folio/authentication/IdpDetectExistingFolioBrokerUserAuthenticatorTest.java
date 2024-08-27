package org.folio.authentication;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.keycloak.models.UserModel.EMAIL;
import static org.keycloak.models.UserModel.USERNAME;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

import java.util.HashMap;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IdpDetectExistingFolioBrokerUserAuthenticatorTest {

  private IdpDetectExistingFolioBrokerUserAuthenticator unit;

  @BeforeEach
  void init() {
    unit = new IdpDetectExistingFolioBrokerUserAuthenticator();
  }

  @Test
  void auth_positive_matchOneByEmail() {
    var result = unit.checkExistingUser(mockAuthFlowContext("customIdAttr",
      query -> "customIdAttr=hello@world".equals(query) ? Stream.of(mockUser("123", "user123", "hello@world"))
        : Stream.empty(), false), "userName", null, mockIdentityContext("hello@world", "user123"));
    assertUserEmail(result, "123", "hello@world");
  }

  @Test
  void auth_negative_matchManyByEmail() {
    var result = unit.checkExistingUser(mockAuthFlowContext("customIdAttr",
        query -> Stream.of(mockUser("123", "user123", "hello@world"), mockUser("124", "user124", "bye@world")), false),
      "userName", null, mockIdentityContext("hello@world", "user123"));

    assertNull(result);
  }

  @Test
  void auth_negative_matchOneByEmailButDuplicateEmailsAllowed() {
    var result = unit.checkExistingUser(mockAuthFlowContext("customIdAttr",
      query -> "customIdAttr=hello@world".equals(query) ? Stream.of(mockUser("123", "user123", "hello@world"))
        : Stream.empty(), true), "userName", null, mockIdentityContext("hello@world", "user123"));
    assertNull(result);
  }

  @Test
  void auth_positive_matchOneByUsername() {
    var result = unit.checkExistingUser(mockAuthFlowContext("customIdAttr",
      query -> "customIdAttr=user123".equals(query) ? Stream.of(mockUser("123", "user123", "hello@world"))
        : Stream.empty(), true), "user123", null, mockIdentityContext("hello@world", "user123"));
    assertUserName(result, "123", "user123");
  }

  @Test
  void auth_negative_matchManyByUsername() {
    var result = unit.checkExistingUser(mockAuthFlowContext("customIdAttr",
      query -> Stream.of(mockUser("123", "user123", "hello@world"), mockUser("124", "user124", "bye@world")), true), "user123", null, mockIdentityContext("hello@world", "user123"));
    assertNull(result);
  }

  protected AuthenticationFlowContext mockAuthFlowContext(String externalIdAttrName,
    Function<String, Stream<UserModel>> usersProviderMock, boolean allowDuplicateEmails) {
    var result = mock(AuthenticationFlowContext.class);
    var realm = mock(RealmModel.class);
    var authConfig = mock(AuthenticatorConfigModel.class);
    var session = mock(KeycloakSession.class);
    var userProvider = mock(UserProvider.class);
    var config = new HashMap<String, String>();
    if (externalIdAttrName != null) {
      config.put(IdpDetectExistingFolioBrokerUserAuthenticatorFactory.EXTERNAL_ID_PROPERTY_NAME, externalIdAttrName);
    }
    lenient().when(result.getAuthenticatorConfig()).thenReturn(authConfig);
    lenient().when(authConfig.getConfig()).thenReturn(config);
    lenient().when(result.getSession()).thenReturn(session);
    lenient().when(session.users()).thenReturn(userProvider);
    lenient().when(realm.isDuplicateEmailsAllowed()).thenReturn(allowDuplicateEmails);
    lenient().when(result.getRealm()).thenReturn(realm);

    lenient().when(userProvider.searchForUserByUserAttributeStream(any(), any(), any())).thenAnswer(invocation -> {
      var attrName = invocation.getArgument(1);
      var attrValue = invocation.getArgument(2);
      return usersProviderMock.apply(attrName + "=" + attrValue);
    });
    return result;
  }

  protected BrokeredIdentityContext mockIdentityContext(String email, String username) {
    var result = mock(BrokeredIdentityContext.class);
    lenient().when(result.getUsername()).thenReturn(username);
    lenient().when(result.getEmail()).thenReturn(email);
    return result;
  }

  protected UserModel mockUser(String id, String username, String email) {
    var result = mock(UserModel.class);
    lenient().when(result.getId()).thenReturn(id);
    lenient().when(result.getUsername()).thenReturn(username);
    lenient().when(result.getEmail()).thenReturn(email);
    return result;
  }

  protected void assertUserEmail(ExistingUserInfo userInfo, String id, String email) {
    assertUserInfo(userInfo, id, EMAIL, email);
  }

  protected void assertUserName(ExistingUserInfo userInfo, String id, String username) {
    assertUserInfo(userInfo, id, USERNAME, username);
  }

  protected void assertUserInfo(ExistingUserInfo userInfo, String id, String attrName, String attrValue) {
    assertNotNull(userInfo);
    assertEquals(id, userInfo.getExistingUserId());
    assertEquals(attrName, userInfo.getDuplicateAttributeName());
    assertEquals(attrValue, userInfo.getDuplicateAttributeValue());
  }
}
