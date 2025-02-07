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
import org.keycloak.models.light.LightweightUserAdapter;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.storage.adapter.InMemoryUserAdapter;

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
  private static final String RESPONSE_JSON = "{\"access_token\":\"token\"}";
  private static final String USER_SET_BEFORE_USERNAME_PASSWORD_AUTH = "USER_SET_BEFORE_USERNAME_PASSWORD_AUTH";

  private FolioEcsUsernamePasswordForm usernamePasswordForm;
  private KeycloakSession session;
  private AuthenticationFlowContext context;
  private HttpRequest httpRequest;
  private UserProvider userProvider;
  private IdentityProviderStorageProvider identityProviderStorageProvider;
  private PasswordHashProvider passwordHashProvider;
  private AuthenticationExecutionModel executionModel;
  private LoginFormsProvider loginFormsProvider;
  private AuthenticationSessionModel authSession;
  private RealmModel realm;
  private FreeMarkerLoginFormsProvider freeMarkerLoginFormsProvider;
  @SuppressWarnings("rawtypes")
  private IdentityProviderFactory identityProviderFactory;

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
    executionModel = mock(AuthenticationExecutionModel.class);
    loginFormsProvider = mock(LoginFormsProvider.class);
    authSession = mock(AuthenticationSessionModel.class);
    realm = mock(RealmModel.class);
    freeMarkerLoginFormsProvider = mock(FreeMarkerLoginFormsProvider.class);
    identityProviderFactory = mock(IdentityProviderFactory.class);

    when(context.getSession()).thenReturn(session);
    when(context.getHttpRequest()).thenReturn(httpRequest);
    when(context.getAuthenticationSession()).thenReturn(authSession);
    when(context.getRealm()).thenReturn(realm);
    when(realm.getName()).thenReturn(REALM);
    when(context.getEvent()).thenReturn(mock(EventBuilder.class));
    when(session.users()).thenReturn(userProvider);

    var keycloakSessionFactory = mock(KeycloakSessionFactory.class);
    when(session.getKeycloakSessionFactory()).thenReturn(keycloakSessionFactory);
    when(keycloakSessionFactory.getProviderFactory(IdentityProvider.class, PROVIDER_ID))
      .thenReturn(identityProviderFactory);
  }

  @Test
  void testActionWithCancellation() {
    var formData = new MultivaluedHashMap<String, String>();
    formData.add("cancel", "");

    when(httpRequest.getDecodedFormParameters()).thenReturn(formData);

    usernamePasswordForm.action(context);

    verify(context).cancelLogin();
  }

  @Test
  void testActionWithFederatedIdentity() {
    var userModel = new LightweightUserAdapter(session, realm, USER_ID);
    userModel.setUsername(USERNAME);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getAllStream()).thenReturn(Stream.of(createIdentityProviderModel()));
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(USERNAME));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);
    when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(createFederatedIdentityModel()));
    when(context.getExecution()).thenReturn(executionModel);
    when(executionModel.getId()).thenReturn(EXECUTION_ID);
    when(context.form()).thenReturn(loginFormsProvider);
    when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
    when(context.getAuthenticationSession()).thenReturn(authSession);

    usernamePasswordForm.action(context);

    verify(context, atMostOnce()).setUser(any(UserModel.class));
    verify(authSession, atMostOnce()).setAuthNote(eq(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH), eq("true"));
    verify(session, atMostOnce()).setAttribute(eq("federatedIdentityModel"), any(FederatedIdentityModel.class));
  }

  @Test
  void testActionWithoutFederatedIdentity() {
    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getAllStream()).thenReturn(Stream.of(createIdentityProviderModel()));
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(USERNAME));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(null);
    when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of());
    when(context.getExecution()).thenReturn(executionModel);
    when(executionModel.getId()).thenReturn(EXECUTION_ID);
    when(context.form()).thenReturn(loginFormsProvider);
    when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
    when(context.getAuthenticationSession()).thenReturn(authSession);

    usernamePasswordForm.action(context);

    verify(context, never()).setUser(any(UserModel.class));
    verify(authSession, never()).setAuthNote(eq(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH), eq("true"));
    verify(session, never()).setAttribute(eq("federatedIdentityModel"), any(FederatedIdentityModel.class));
  }

  @Test
  void testActionWithFederatedIdentityAndWithNoUsername() {
    var userModel = new LightweightUserAdapter(session, realm, USER_ID);
    userModel.setUsername(USERNAME);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getAllStream()).thenReturn(Stream.of(createIdentityProviderModel()));
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);
    when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(createFederatedIdentityModel()));
    when(context.getExecution()).thenReturn(executionModel);
    when(executionModel.getId()).thenReturn(EXECUTION_ID);
    when(context.form()).thenReturn(loginFormsProvider);
    when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
    when(context.getAuthenticationSession()).thenReturn(authSession);

    usernamePasswordForm.action(context);

    verify(context, atMostOnce()).setUser(any());
    verify(authSession, atMostOnce()).setAuthNote(any(), any());
    verify(session, atMostOnce()).setAttribute(any(), any());
    verify(context, atMostOnce()).failureChallenge(eq(AuthenticationFlowError.INVALID_USER), any(Response.class));
  }

  @ParameterizedTest
  @ValueSource(strings = {UserModel.EMAIL, UserModel.USERNAME})
  void testActionWithFederatedIdentityAndWithDuplicatedUsername(String field) {
    var userModel = new LightweightUserAdapter(session, realm, USER_ID);
    userModel.setUsername(USERNAME);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getAllStream()).thenReturn(Stream.of(createIdentityProviderModel()));
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(USERNAME));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenThrow(
      new ModelDuplicateException("Exception", field));
    when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(
      Stream.of(createFederatedIdentityModel()));
    when(context.getExecution()).thenReturn(executionModel);
    when(executionModel.getId()).thenReturn(EXECUTION_ID);
    when(context.form()).thenReturn(loginFormsProvider);
    when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
    when(loginFormsProvider.setError(anyString(), eq(new Object[0]))).thenReturn(loginFormsProvider);
    when(freeMarkerLoginFormsProvider.createResponse(any())).thenReturn(mock(Response.class));
    when(loginFormsProvider.createLoginUsernamePassword()).thenReturn(mock(Response.class));
    when(context.getAuthenticationSession()).thenReturn(authSession);

    usernamePasswordForm.action(context);

    verify(context, atMostOnce()).setUser(any());
    verify(authSession, times(3)).setAuthNote(any(), any());
    verify(session, atMostOnce()).setAttribute(any(), any());
    verify(context, atMostOnce()).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS),
      any(Response.class));
  }

  @Test
  void testValidatePasswordWithFederatedIdentity() throws IOException {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(createIdentityProviderModel());
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);

    var config = mock(OIDCIdentityProviderConfig.class);
    when(config.getTokenUrl()).thenReturn(URL);
    when(config.getClientId()).thenReturn(CLIENT_ID);
    when(config.getClientSecret()).thenReturn(CLIENT_SECRET);

    var oidcIdentityProvider = mock(OIDCIdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(oidcIdentityProvider);
    when(oidcIdentityProvider.getConfig()).thenReturn(config);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = mock(CloseableHttpResponse.class);
      when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
      when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

      var httpEntity = mock(HttpEntity.class);
      when(httpResponse.getEntity()).thenReturn(httpEntity);
      when(httpEntity.getContentType()).thenReturn(mock(Header.class));
      when(httpEntity.getContent()).thenReturn(mock(InputStream.class));

      var httpClient = mock(CloseableHttpClient.class);
      when(httpClient.execute(any())).thenReturn(httpResponse);
      mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8)))
        .thenReturn(RESPONSE_JSON);
      var httpClientProvider = mock(HttpClientProvider.class);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
      when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
      when(context.getExecution()).thenReturn(executionModel);
      when(executionModel.getId()).thenReturn(EXECUTION_ID);
      when(context.form()).thenReturn(loginFormsProvider);
      when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
      when(context.getAuthenticationSession()).thenReturn(authSession);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

      assertTrue(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoIdentityProviderFactory() {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(createIdentityProviderModel());
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);

    var config = mock(OIDCIdentityProviderConfig.class);
    when(config.getTokenUrl()).thenReturn(URL);
    when(config.getClientId()).thenReturn(CLIENT_ID);
    when(config.getClientSecret()).thenReturn(CLIENT_SECRET);

    var keycloakSessionFactory = mock(KeycloakSessionFactory.class);
    when(session.getKeycloakSessionFactory()).thenReturn(keycloakSessionFactory);
    when(keycloakSessionFactory.getProviderFactory(IdentityProvider.class, PROVIDER_ID))
      .thenReturn(null);

    var oidcIdentityProvider = mock(OIDCIdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(oidcIdentityProvider);
    when(oidcIdentityProvider.getConfig()).thenReturn(config);

    when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
    when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
    when(context.getExecution()).thenReturn(executionModel);
    when(executionModel.getId()).thenReturn(EXECUTION_ID);
    when(context.form()).thenReturn(loginFormsProvider);
    when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
    when(context.getAuthenticationSession()).thenReturn(authSession);

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

    assertFalse(result);

    verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoIdentityProviderModel() throws IOException {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(null);
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);

    var config = mock(OIDCIdentityProviderConfig.class);
    when(config.getTokenUrl()).thenReturn(URL);
    when(config.getClientId()).thenReturn(CLIENT_ID);
    when(config.getClientSecret()).thenReturn(CLIENT_SECRET);

    var oidcIdentityProvider = mock(OIDCIdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(oidcIdentityProvider);
    when(oidcIdentityProvider.getConfig()).thenReturn(config);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = mock(CloseableHttpResponse.class);
      when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
      when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

      var httpEntity = mock(HttpEntity.class);
      when(httpResponse.getEntity()).thenReturn(httpEntity);
      when(httpEntity.getContentType()).thenReturn(mock(Header.class));
      when(httpEntity.getContent()).thenReturn(mock(InputStream.class));

      var httpClient = mock(CloseableHttpClient.class);
      when(httpClient.execute(any())).thenReturn(httpResponse);
      mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8)))
        .thenReturn(RESPONSE_JSON);
      var httpClientProvider = mock(HttpClientProvider.class);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(federatedIdentityModel.getIdentityProvider()).thenReturn(null);
      when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
      when(context.getExecution()).thenReturn(executionModel);
      when(executionModel.getId()).thenReturn(EXECUTION_ID);
      when(context.form()).thenReturn(loginFormsProvider);
      when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
      when(context.getAuthenticationSession()).thenReturn(authSession);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithLinkOnlyIdentityProviderModel() throws IOException {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    var identityProviderModel = createIdentityProviderModel();
    identityProviderModel.setLinkOnly(true);
    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(identityProviderModel);
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);

    var config = mock(OIDCIdentityProviderConfig.class);
    when(config.getTokenUrl()).thenReturn(URL);
    when(config.getClientId()).thenReturn(CLIENT_ID);
    when(config.getClientSecret()).thenReturn(CLIENT_SECRET);

    var oidcIdentityProvider = mock(OIDCIdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(oidcIdentityProvider);
    when(oidcIdentityProvider.getConfig()).thenReturn(config);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = mock(CloseableHttpResponse.class);
      when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
      when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

      var httpEntity = mock(HttpEntity.class);
      when(httpResponse.getEntity()).thenReturn(httpEntity);
      when(httpEntity.getContentType()).thenReturn(mock(Header.class));
      when(httpEntity.getContent()).thenReturn(mock(InputStream.class));

      var httpClient = mock(CloseableHttpClient.class);
      when(httpClient.execute(any())).thenReturn(httpResponse);
      mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8)))
        .thenReturn(RESPONSE_JSON);
      var httpClientProvider = mock(HttpClientProvider.class);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
      when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
      when(context.getExecution()).thenReturn(executionModel);
      when(executionModel.getId()).thenReturn(EXECUTION_ID);
      when(context.form()).thenReturn(loginFormsProvider);
      when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
      when(context.getAuthenticationSession()).thenReturn(authSession);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithDisabledFederatedIdentity() throws IOException {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    var identityProviderModel = createIdentityProviderModel();
    identityProviderModel.setEnabled(false);
    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(identityProviderModel);
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);

    var config = mock(OIDCIdentityProviderConfig.class);
    when(config.getTokenUrl()).thenReturn(URL);
    when(config.getClientId()).thenReturn(CLIENT_ID);
    when(config.getClientSecret()).thenReturn(CLIENT_SECRET);

    var oidcIdentityProvider = mock(OIDCIdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(oidcIdentityProvider);
    when(oidcIdentityProvider.getConfig()).thenReturn(config);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = mock(CloseableHttpResponse.class);
      when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
      when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

      var httpEntity = mock(HttpEntity.class);
      when(httpResponse.getEntity()).thenReturn(httpEntity);
      when(httpEntity.getContentType()).thenReturn(mock(Header.class));
      when(httpEntity.getContent()).thenReturn(mock(InputStream.class));

      var httpClient = mock(CloseableHttpClient.class);
      when(httpClient.execute(any())).thenReturn(httpResponse);
      mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8)))
        .thenReturn(RESPONSE_JSON);
      var httpClientProvider = mock(HttpClientProvider.class);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
      when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
      when(context.getExecution()).thenReturn(executionModel);
      when(executionModel.getId()).thenReturn(EXECUTION_ID);
      when(context.form()).thenReturn(loginFormsProvider);
      when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
      when(context.getAuthenticationSession()).thenReturn(authSession);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoIdentityProvider() throws IOException {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(createIdentityProviderModel());
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);
    when(identityProviderFactory.create(any(), any())).thenReturn(null);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = mock(CloseableHttpResponse.class);
      when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
      when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

      var httpEntity = mock(HttpEntity.class);
      when(httpResponse.getEntity()).thenReturn(httpEntity);
      when(httpEntity.getContentType()).thenReturn(mock(Header.class));
      when(httpEntity.getContent()).thenReturn(mock(InputStream.class));

      var httpClient = mock(CloseableHttpClient.class);
      when(httpClient.execute(any())).thenReturn(httpResponse);
      mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8)))
        .thenReturn(RESPONSE_JSON);
      var httpClientProvider = mock(HttpClientProvider.class);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
      when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
      when(context.getExecution()).thenReturn(executionModel);
      when(executionModel.getId()).thenReturn(EXECUTION_ID);
      when(context.form()).thenReturn(loginFormsProvider);
      when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
      when(context.getAuthenticationSession()).thenReturn(authSession);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithWrongIdentityProvider() throws IOException {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(createIdentityProviderModel());
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);

    var identityProvider = mock(IdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(identityProvider);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = mock(CloseableHttpResponse.class);
      when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
      when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

      var httpEntity = mock(HttpEntity.class);
      when(httpResponse.getEntity()).thenReturn(httpEntity);
      when(httpEntity.getContentType()).thenReturn(mock(Header.class));
      when(httpEntity.getContent()).thenReturn(mock(InputStream.class));

      var httpClient = mock(CloseableHttpClient.class);
      when(httpClient.execute(any())).thenReturn(httpResponse);
      mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8)))
        .thenReturn(RESPONSE_JSON);
      var httpClientProvider = mock(HttpClientProvider.class);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
      when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
      when(context.getExecution()).thenReturn(executionModel);
      when(executionModel.getId()).thenReturn(EXECUTION_ID);
      when(context.form()).thenReturn(loginFormsProvider);
      when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
      when(context.getAuthenticationSession()).thenReturn(authSession);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoAccessToken() throws IOException {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(createIdentityProviderModel());
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);

    var config = mock(OIDCIdentityProviderConfig.class);
    when(config.getTokenUrl()).thenReturn(URL);
    when(config.getClientId()).thenReturn(CLIENT_ID);
    when(config.getClientSecret()).thenReturn(CLIENT_SECRET);

    var oidcIdentityProvider = mock(OIDCIdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(oidcIdentityProvider);
    when(oidcIdentityProvider.getConfig()).thenReturn(config);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = mock(CloseableHttpResponse.class);
      when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
      when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

      var httpEntity = mock(HttpEntity.class);
      when(httpResponse.getEntity()).thenReturn(httpEntity);
      when(httpEntity.getContentType()).thenReturn(mock(Header.class));
      when(httpEntity.getContent()).thenReturn(mock(InputStream.class));

      var httpClient = mock(CloseableHttpClient.class);
      when(httpClient.execute(any())).thenReturn(httpResponse);
      mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8))).thenReturn("");
      var httpClientProvider = mock(HttpClientProvider.class);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
      when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
      when(context.getExecution()).thenReturn(executionModel);
      when(executionModel.getId()).thenReturn(EXECUTION_ID);
      when(context.form()).thenReturn(loginFormsProvider);
      when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
      when(context.getAuthenticationSession()).thenReturn(authSession);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithFederatedIdentityAndWithNoOkStatus() throws IOException {
    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var federatedIdentityModel = mock(FederatedIdentityModel.class);
    when(federatedIdentityModel.getUserName()).thenReturn(USERNAME);
    when(context.getSession().removeAttribute("federatedIdentityModel")).thenReturn(federatedIdentityModel);

    when(session.identityProviders()).thenReturn(identityProviderStorageProvider);
    when(session.identityProviders().getByAlias(PROVIDER_ALIAS)).thenReturn(createIdentityProviderModel());
    when(session.users()).thenReturn(userProvider);
    when(session.getProvider(PasswordHashProvider.class)).thenReturn(passwordHashProvider);
    when(httpRequest.getDecodedFormParameters()).thenReturn(createFormData(null));
    when(userProvider.getUserByFederatedIdentity(any(), any())).thenReturn(userModel);

    var config = mock(OIDCIdentityProviderConfig.class);
    when(config.getTokenUrl()).thenReturn(URL);
    when(config.getClientId()).thenReturn(CLIENT_ID);
    when(config.getClientSecret()).thenReturn(CLIENT_SECRET);

    var oidcIdentityProvider = mock(OIDCIdentityProvider.class);
    when(identityProviderFactory.create(any(), any())).thenReturn(oidcIdentityProvider);
    when(oidcIdentityProvider.getConfig()).thenReturn(config);

    try (var mockedStatic = mockStatic(EntityUtils.class)) {
      var httpResponse = mock(CloseableHttpResponse.class);
      when(httpResponse.getStatusLine()).thenReturn(mock(StatusLine.class));
      when(httpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_GATEWAY_TIMEOUT);

      var httpEntity = mock(HttpEntity.class);
      when(httpResponse.getEntity()).thenReturn(httpEntity);
      when(httpEntity.getContentType()).thenReturn(mock(Header.class));
      when(httpEntity.getContent()).thenReturn(mock(InputStream.class));

      var httpClient = mock(CloseableHttpClient.class);
      when(httpClient.execute(any())).thenReturn(httpResponse);
      mockedStatic.when(() -> EntityUtils.toString(eq(httpEntity), eq(StandardCharsets.UTF_8))).thenReturn("");
      var httpClientProvider = mock(HttpClientProvider.class);
      when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
      when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
      when(federatedIdentityModel.getIdentityProvider()).thenReturn(PROVIDER_ALIAS);
      when(userProvider.getFederatedIdentitiesStream(any(), any())).thenReturn(Stream.of(federatedIdentityModel));
      when(context.getExecution()).thenReturn(executionModel);
      when(executionModel.getId()).thenReturn(EXECUTION_ID);
      when(context.form()).thenReturn(loginFormsProvider);
      when(loginFormsProvider.setExecution(anyString())).thenReturn(loginFormsProvider);
      when(context.getAuthenticationSession()).thenReturn(authSession);

      var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

      assertFalse(result);

      verify(userModel.credentialManager(), never()).isValid(any(CredentialInput[].class));
    }
  }

  @Test
  void testValidatePasswordWithNoFederatedIdentity() {
    when(session.removeAttribute("federatedIdentityModel")).thenReturn(null);

    var userModel = mock(InMemoryUserAdapter.class);
    when(userModel.getId()).thenReturn(USER_ID);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.getUsername()).thenReturn(USERNAME);
    when(userModel.credentialManager()).thenReturn(mock(CredentialModel.SECRET));
    when(userModel.credentialManager().isValid(any(CredentialInput[].class))).thenReturn(true);

    var result = usernamePasswordForm.validatePassword(context, userModel, createFormData(USERNAME), true);

    assertTrue(result);

    verify(userModel.credentialManager(), atMostOnce()).isValid(any(CredentialInput[].class));
  }

  private MultivaluedHashMap<String, String> createFormData(String username) {
    var formData = new MultivaluedHashMap<String, String>();
    formData.add("username", username);
    formData.add("password", FolioEcsUsernamePasswordFormTest.PASSWORD);
    return formData;
  }

  private FederatedIdentityModel createFederatedIdentityModel() {
    return new FederatedIdentityModel(PROVIDER_ALIAS, USERNAME, null);
  }

  private IdentityProviderModel createIdentityProviderModel() {
    var identityProviderModel = new IdentityProviderModel();
    identityProviderModel.setProviderId(PROVIDER_ID);
    identityProviderModel.setAlias(PROVIDER_ALIAS);
    identityProviderModel.setEnabled(true);
    return identityProviderModel;
  }
}
