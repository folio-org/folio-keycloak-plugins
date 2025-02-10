package org.folio.authentication;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atMostOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.adapter.InMemoryUserAdapter;
import org.mockito.MockedStatic;

class FolioEcsUsernamePasswordFormTest {

  private static final String USER_ID = "userId";
  private static final String USERNAME = "username";
  private static final String PASSWORD = "password";
  private static final String PROVIDER_ID = "providerId";
  private static final String PROVIDER_ALIAS = "providerAlias";
  private static final String REALM = "realm";
  private static final String EXECUTION_ID = "executionId";
  private static final String URL = "url";
  private static final String CLIENT_ID = "clientId";
  private static final String CLIENT_SECRET = "clientSecret";
  private static final String FEDERATED_IDENTITY_MODEL = "federatedIdentityModel";
  private static final String TRUE = "true";
  private static final String RESPONSE_JSON = "{\"access_token\":\"token\"}";
  private static final String USER_SET_BEFORE_USERNAME_PASSWORD_AUTH = "USER_SET_BEFORE_USERNAME_PASSWORD_AUTH";

  private FolioEcsUsernamePasswordForm usernamePasswordForm;
  private KeycloakSession session;
  private AuthenticationFlowContext context;
  private HttpRequest httpRequest;
  private UserProvider userProvider;
  private IdentityProviderStorageProvider identityProviderStorageProvider;
  private PasswordHashProvider passwordHashProvider;
  private LoginFormsProvider loginFormsProvider;
  private AuthenticationSessionModel authSession;
  private FreeMarkerLoginFormsProvider freeMarkerLoginFormsProvider;
  @SuppressWarnings("rawtypes")
  private IdentityProviderFactory identityProviderFactory;
  private KeycloakSessionFactory keycloakSessionFactory;

  @BeforeEach
  @SuppressWarnings("unchecked")
  void setUp() {
    usernamePasswordForm = new FolioEcsUsernamePasswordForm();

    session = mock(KeycloakSession.class);
    context = mock(AuthenticationFlowContext.class);
    httpRequest = mock(HttpRequest.class);
    userProvider = mock(UserProvider.class);
    identityProviderStorageProvider = mock(IdentityProviderStorageProvider.class);
    passwordHashProvider = mock(PasswordHashProvider.class);

    loginFormsProvider = mock(LoginFormsProvider.class);
    authSession = mock(AuthenticationSessionModel.class);
    freeMarkerLoginFormsProvider = mock(FreeMarkerLoginFormsProvider.class);
    identityProviderFactory = mock(IdentityProviderFactory.class);
    keycloakSessionFactory = mock(KeycloakSessionFactory.class);

    when(context.getSession()).thenReturn(session);
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getEvent()).thenReturn(mock(EventBuilder.class));

    var realm = mock(RealmModel.class);
    when(context.getRealm()).thenReturn(realm);
    when(realm.getName()).thenReturn(REALM);

    var executionModel = mock(AuthenticationExecutionModel.class);
    when(context.getExecution()).thenReturn(executionModel);
    when(executionModel.getId()).thenReturn(EXECUTION_ID);

    when(context.form()).thenReturn(loginFormsProvider);
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(session.users()).thenReturn(userProvider);
    when(session.getKeycloakSessionFactory()).thenReturn(keycloakSessionFactory);
    when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
    when(keycloakSessionFactory.getProviderFactory(IdentityProvider.class, PROVIDER_ID))
      .thenReturn(identityProviderFactory);
  }

  // Action Tests

  @Test
  void testActionWithCancellation() {
    // With Cancel Form Data Field
    var formData = new MultivaluedHashMap<String, String>();
    formData.add("cancel", "");

    when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

    usernamePasswordForm.action(context);

    verify(context).cancelLogin();
  }

  @Test
  void testActionWithFederatedIdentity() {
    createIdentityProviders();
    createPasswordHashProvider(USERNAME);
    // With Federated Identity
    var userModel = createInMemoryUserAdapterUserModel();
    createFederatedIdentities(userModel, Stream.of(createFederatedIdentityModelObj()));

    usernamePasswordForm.action(context);

    verify(context, atMostOnce()).setUser(any(UserModel.class));
    verify(authSession, atMostOnce()).setAuthNote(eq(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH), eq(TRUE));
    verify(session, atMostOnce()).setAttribute(eq(FEDERATED_IDENTITY_MODEL), any(FederatedIdentityModel.class));
  }

  @Test
  void testActionWithNoFederatedIdentity() {
    createIdentityProviders();
    createPasswordHashProvider(USERNAME);
    // No Federated Identity
    createFederatedIdentities(null, Stream.of());

    usernamePasswordForm.action(context);

    verify(context, never()).setUser(any(UserModel.class));
    verify(authSession, never()).setAuthNote(eq(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH), eq(TRUE));
    verify(session, never()).setAttribute(eq(FEDERATED_IDENTITY_MODEL), any(FederatedIdentityModel.class));
  }

  @Test
  void testActionWithFederatedIdentityAndWithNoUsername() {
    createIdentityProviders();
    // No Username
    createPasswordHashProvider(null);
    var userModel = createInMemoryUserAdapterUserModel();
    createFederatedIdentities(userModel, Stream.of(createFederatedIdentityModelObj()));

    usernamePasswordForm.action(context);

    verify(context, atMostOnce()).setUser(any());
    verify(authSession, atMostOnce()).setAuthNote(any(), any());
    verify(session, atMostOnce()).setAttribute(any(), any());
    verify(context, atMostOnce()).failureChallenge(eq(AuthenticationFlowError.INVALID_USER), any(Response.class));
  }

  @ParameterizedTest
  @ValueSource(strings = {UserModel.EMAIL, UserModel.USERNAME})
  void testActionWithFederatedIdentityAndWithDuplicatedUsername(String field) {
    createIdentityProviders();
    createPasswordHashProvider(USERNAME);

    // Duplicated Email or Username Field
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenThrow(
      new ModelDuplicateException("Exception", field));
    when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(
      Stream.of(createFederatedIdentityModelObj()));
    when(loginFormsProvider.setError(anyString(), eq(new Object[0]))).thenReturn(loginFormsProvider);
    when(freeMarkerLoginFormsProvider.createResponse(any())).thenReturn(mock(Response.class));
    when(loginFormsProvider.createLoginUsernamePassword()).thenReturn(mock(Response.class));

    usernamePasswordForm.action(context);

    verify(context, atMostOnce()).setUser(any());
    verify(authSession, times(3)).setAuthNote(any(), any());
    verify(session, atMostOnce()).setAttribute(any(), any());
    verify(context, atMostOnce()).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS),
      any(Response.class));
  }

  // Validate Password Tests

  @Test
  void testValidatePasswordWithFederatedIdentity() throws IOException {
    createIdentityProviderByAlias(createIdentityProviderModelObj());
    var oidcIdentityProviderConfig = createOidcIdentityProviderConfig();
    createOidcIdentityProvider(oidcIdentityProviderConfig);
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    // With Federated Identity
    bindFederatedIdentity(userModel);
    createPasswordHashProvider(USERNAME);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = createHttpResponse(HttpStatus.SC_OK);
      var httpEntity = createHttpEntity(httpResponse);
      var httpClient = createHttpClient(httpResponse, mockedStatic, httpEntity, RESPONSE_JSON);
      createHttpClientProvider(httpClient);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

      assertTrue(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoIdentityProviderFactory() {
    createIdentityProviderByAlias(createIdentityProviderModelObj());
    var oidcIdentityProviderConfig = createOidcIdentityProviderConfig();
    createOidcIdentityProvider(oidcIdentityProviderConfig);
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);

    // No Identity Provider Factory
    when(keycloakSessionFactory.getProviderFactory(IdentityProvider.class, PROVIDER_ID))
      .thenReturn(null);

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

    assertFalse(result);

    verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoIdentityProviderModel() {
    // No Identity Provider Model
    createIdentityProviderByAlias(null);
    var oidcIdentityProviderConfig = createOidcIdentityProviderConfig();
    createOidcIdentityProvider(oidcIdentityProviderConfig);
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

    assertFalse(result);

    verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
  }

  @Test
  void testValidatePasswordWithDisabledFederatedIdentity() {
    // Disabled Identity Provider
    var identityProviderModel = createIdentityProviderModelObj();
    identityProviderModel.setEnabled(false);
    createIdentityProviderByAlias(identityProviderModel);
    var oidcIdentityProviderConfig = createOidcIdentityProviderConfig();
    createOidcIdentityProvider(oidcIdentityProviderConfig);
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

    assertFalse(result);

    verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithLinkOnlyIdentityProviderModel() {
    // Link Only Identity Provider
    var identityProviderModel = createIdentityProviderModelObj();
    identityProviderModel.setLinkOnly(true);
    createIdentityProviderByAlias(identityProviderModel);
    var oidcIdentityProviderConfig = createOidcIdentityProviderConfig();
    createOidcIdentityProvider(oidcIdentityProviderConfig);
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

    assertFalse(result);

    verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoIdentityProvider() {
    createIdentityProviderByAlias(createIdentityProviderModelObj());
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);

    // No Identity Provider
    when(identityProviderFactory.create(any(), any())).thenReturn(null);

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

    assertFalse(result);

    verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithWrongIdentityProvider() {
    createIdentityProviderByAlias(createIdentityProviderModelObj());
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);

    // Wrong Identity Provider
    when(identityProviderFactory.create(any(), any())).thenReturn(mock(IdentityProvider.class));

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

    assertFalse(result);

    verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoAccessToken() throws IOException {
    createIdentityProviderByAlias(createIdentityProviderModelObj());
    var oidcIdentityProviderConfig = createOidcIdentityProviderConfig();
    createOidcIdentityProvider(oidcIdentityProviderConfig);
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);
    createPasswordHashProvider(null);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = createHttpResponse(HttpStatus.SC_OK);
      var httpEntity = createHttpEntity(httpResponse);
      // No Access Token
      var httpClient = createHttpClient(httpResponse, mockedStatic, httpEntity, "");
      createHttpClientProvider(httpClient);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoOkStatus() throws IOException {
    createIdentityProviderByAlias(createIdentityProviderModelObj());
    var oidcIdentityProviderConfig = createOidcIdentityProviderConfig();
    createOidcIdentityProvider(oidcIdentityProviderConfig);
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);
    createPasswordHashProvider(null);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      // No OK Status (Error code 504)
      var httpResponse = createHttpResponse(HttpStatus.SC_GATEWAY_TIMEOUT);
      var httpEntity = createHttpEntity(httpResponse);
      var httpClient = createHttpClient(httpResponse, mockedStatic, httpEntity, "");
      createHttpClientProvider(httpClient);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void testValidatePasswordWithFederatedIdentityAndWithNoClientSecret(boolean emptyClientSecret) throws IOException {
    createIdentityProviderByAlias(createIdentityProviderModelObj());
    var oidcIdentityProviderConfig = mock(OIDCIdentityProviderConfig.class);
    when(oidcIdentityProviderConfig.getTokenUrl()).thenReturn(URL);
    when(oidcIdentityProviderConfig.getClientId()).thenReturn(CLIENT_ID);
    when(oidcIdentityProviderConfig.getClientSecret()).thenReturn(emptyClientSecret ? "" : null);
    createOidcIdentityProvider(oidcIdentityProviderConfig);
    var federatedIdentityModel = createFederatedIdentityModelWithRemoveAttr();
    bindIdentityProviderAndFederatedIdentityModel(federatedIdentityModel);
    var userModel = createInMemoryUserAdapterUserModel();
    bindFederatedIdentity(userModel);
    createPasswordHashProvider(null);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      // No OK Status (Error code 504)
      var httpResponse = createHttpResponse(HttpStatus.SC_GATEWAY_TIMEOUT);
      var httpEntity = createHttpEntity(httpResponse);
      var httpClient = createHttpClient(httpResponse, mockedStatic, httpEntity, "");
      createHttpClientProvider(httpClient);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithNoFederatedIdentity() {
    var userModel = createInMemoryUserAdapterUserModel();

    // No Federated Identity
    when(session.removeAttribute(FEDERATED_IDENTITY_MODEL)).thenReturn(null);

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormDataObj(USERNAME), true);

    assertTrue(result);

    verify(userModel.credentialManager(), atMostOnce()).isValid(any(CredentialInput[].class));
  }

  // Utility Methods

  private MultivaluedHashMap<String, String> createFormDataObj(String username) {
    var formData = new MultivaluedHashMap<String, String>();
    formData.add("username", username);
    formData.add("password", FolioEcsUsernamePasswordFormTest.PASSWORD);
    return formData;
  }

  private IdentityProviderModel createIdentityProviderModelObj() {
    var identityProviderModel = new IdentityProviderModel();
    identityProviderModel.setProviderId(PROVIDER_ID);
    identityProviderModel.setAlias(PROVIDER_ALIAS);
    identityProviderModel.setEnabled(true);
    return identityProviderModel;
  }

  private void createIdentityProviders() {
    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getAllStream()).thenReturn(Stream.of(createIdentityProviderModelObj()));
  }

  private void createIdentityProviderByAlias(IdentityProviderModel identityProviderModelObj) {
    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(identityProviderModelObj);
  }

  private FederatedIdentityModel createFederatedIdentityModelWithRemoveAttr() {
    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute(FEDERATED_IDENTITY_MODEL)).thenReturn(federatedIdentityModel);
    return federatedIdentityModel;
  }

  private void createPasswordHashProvider(String username) {
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormDataObj(username));
  }

  private FederatedIdentityModel createFederatedIdentityModelObj() {
    return new FederatedIdentityModel(PROVIDER_ALIAS, USERNAME, null);
  }

  private void bindFederatedIdentity(UserModel userModel) {
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);
  }

  private void createFederatedIdentities(UserModel userModel,
                                         Stream<FederatedIdentityModel> federatedIdentityModelObj) {
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);
    when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(federatedIdentityModelObj);
  }

  private void bindIdentityProviderAndFederatedIdentityModel(FederatedIdentityModel federatedIdentityModel) {
    when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
    when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
  }

  private InMemoryUserAdapter createInMemoryUserAdapterUserModel() {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);
    return userModel;
  }

  private OIDCIdentityProviderConfig createOidcIdentityProviderConfig() {
    var config = mock(OIDCIdentityProviderConfig.class);
    when(config.getTokenUrl()).thenReturn(URL);
    when(config.getClientId()).thenReturn(CLIENT_ID);
    when(config.getClientSecret()).thenReturn(CLIENT_SECRET);
    return config;
  }

  private void createOidcIdentityProvider(OIDCIdentityProviderConfig oidcIdentityProviderConfig) {
    var oidcIdentityProvider = mock(OIDCIdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(oidcIdentityProvider);
    when(oidcIdentityProvider.getConfig()).thenReturn(oidcIdentityProviderConfig);
  }

  private void createHttpClientProvider(CloseableHttpClient httpClient) {
    var httpClientProvider = mock(HttpClientProvider.class);
    when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
    when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
  }

  private HttpEntity createHttpEntity(CloseableHttpResponse httpResponse) throws IOException {
    var httpEntity = mock(HttpEntity.class);
    when(httpResponse.getEntity()).thenReturn(httpEntity);
    when(httpEntity.getContentType()).thenReturn(mock(Header.class));
    when(httpEntity.getContent()).thenReturn(mock(InputStream.class));
    return httpEntity;
  }

  private CloseableHttpClient createHttpClient(CloseableHttpResponse httpResponse,
                                               MockedStatic<EntityUtils> mockedStatic,
                                               HttpEntity httpEntity, String responseJson) throws IOException {
    var httpClient = mock(CloseableHttpClient.class);
    when(httpClient.execute(any())).thenReturn(httpResponse);
    mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8)))
      .thenReturn(responseJson);
    return httpClient;
  }

  private CloseableHttpResponse createHttpResponse(int scOk) {
    var httpResponse = mock(CloseableHttpResponse.class);
    when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
    when(httpResponse.getStatusLine().getStatusCode()).thenReturn(scOk);
    return httpResponse;
  }
}
