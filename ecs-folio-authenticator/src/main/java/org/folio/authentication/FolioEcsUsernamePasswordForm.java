package org.folio.authentication;

import static org.keycloak.services.validation.Validation.FIELD_USERNAME;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthenticationException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.IdentityProviderFactory;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderQuery;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

public class FolioEcsUsernamePasswordForm extends UsernamePasswordForm {

  private static final Logger log = Logger.getLogger(FolioEcsUsernamePasswordForm.class);

  private static final String FEDERATED_IDENTITY_MODEL = "federatedIdentityModel";

  @Override
  public void action(AuthenticationFlowContext context) {
    MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    if (formData.containsKey("cancel")) {
      log.debugf("getUserFromForm:: Cancelling authentication");
      context.cancelLogin();
      return;
    }

    UserModel userModel = getUserFromForm(context, formData);

    Optional<FederatedIdentityModel> identityModelOptional =
      context.getSession().users().getFederatedIdentitiesStream(context.getRealm(), userModel).findFirst();

    if (identityModelOptional.isPresent()) {
      log.debugf("getUserFromForm:: Using federated identity authentication");
      FederatedIdentityModel federatedIdentityModel = identityModelOptional.get();
      context.setUser(userModel);
      context.getAuthenticationSession().setAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH, "true");
      context.getSession().setAttribute(FEDERATED_IDENTITY_MODEL, federatedIdentityModel);
    } else {
      log.debugf("getUserFromForm:: Using non-federated identity authentication");
    }
    super.action(context);
  }

  @Override
  public boolean validatePassword(AuthenticationFlowContext context, UserModel user,
                                  MultivaluedMap<String, String> inputData, boolean clearUser) {
    FederatedIdentityModel federatedIdentityModel =
      (FederatedIdentityModel) context.getSession().removeAttribute(FEDERATED_IDENTITY_MODEL);
    if (federatedIdentityModel == null) {
      log.debugf("getUserFromForm:: Validating password in non-federated mode");
      return super.validatePassword(context, user, inputData, clearUser);
    }

    log.debugf("getUserFromForm:: Validating password in federated mode");
    boolean check = authenticateBy(context, federatedIdentityModel);
    return check || badPasswordHandler(context, user);
  }

  private UserModel getUserFromForm(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
    String username = Optional.ofNullable(inputData.getFirst(AuthenticationManager.FORM_USERNAME))
      .orElse("")
      .trim().toLowerCase();
    if (username.isEmpty()) {
      context.getEvent().error(Errors.USER_NOT_FOUND);
      Response challengeResponse = challenge(context, getDefaultChallengeMessage(context), FIELD_USERNAME);
      context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
      log.warnf("getUserFromForm:: Cannot retrieve user from form username is empty");
      return null;
    }

    context.getEvent().detail(Details.USERNAME, username);
    context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

    UserModel user;
    try {
      KeycloakSession keycloakSession = context.getSession();
      RealmModel realm = context.getRealm();

      user = keycloakSession.identityProviders()
        .getAllStream(IdentityProviderQuery.userAuthentication())
        .map(idp -> getUserFromFederatedIdentity(idp, keycloakSession, realm, username))
        .filter(Objects::nonNull).findFirst()
        .orElseGet(() -> KeycloakModelUtils.findUserByNameOrEmail(keycloakSession, realm, username));
    } catch (ModelDuplicateException mde) {
      ServicesLogger.LOGGER.modelDuplicateException(mde);

      Response challengeResponse;
      if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
        challengeResponse = setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS,
          AuthenticationFlowError.INVALID_USER);
        log.warnf("getUserFromForm:: Cannot retrieve user from from, email is duplicated");
      } else {
        challengeResponse = setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS,
          AuthenticationFlowError.INVALID_USER);
        log.warnf("getUserFromForm:: Cannot retrieve user from form, username is duplicated");
      }
      context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
      return null;
    }
    testInvalidUser(context, user);
    return user;
  }

  private UserModel getUserFromFederatedIdentity(IdentityProviderModel idp, KeycloakSession keycloakSession,
                                                 RealmModel realm, String username) {
    return keycloakSession.users()
        .getUserByFederatedIdentity(realm, new FederatedIdentityModel(idp.getAlias(), username, null));
  }

  private boolean badPasswordHandler(AuthenticationFlowContext context, UserModel user) {
    context.getEvent().user(user);
    context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
    context.getAuthenticationSession().removeAuthNote(USER_SET_BEFORE_USERNAME_PASSWORD_AUTH);

    Response challengeResponse = challenge(context, Messages.INVALID_USER, FIELD_USERNAME);
    context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
    context.clearUser();
    return false;
  }

  private boolean authenticateBy(AuthenticationFlowContext context, FederatedIdentityModel federatedIdentityModel) {
    String providerAlias = federatedIdentityModel.getIdentityProvider();
    IdentityProvider<?> idpInstance = getValidatedIdentityProvider(context, providerAlias);
    if (idpInstance == null) {
      log.warnf("authenticateBy:: Cannot find an identity provider");
      return false;
    }
    if (idpInstance instanceof OIDCIdentityProvider oidcIdentityProvider) {
      log.debugf("authenticateBy:: Found an OIDCIdentityProvider identity provider %s", providerAlias);
      return authenticateWithOidcProvider(context, oidcIdentityProvider, federatedIdentityModel);
    }
    log.warnf("authenticateBy:: IdentityProvider %s is not an instance of OIDCIdentityProvider", providerAlias);
    return false;
  }

  private IdentityProvider<?> getValidatedIdentityProvider(AuthenticationFlowContext context, String providerAlias) {
    IdentityProviderModel idpModel = context.getSession().identityProviders().getByAlias(providerAlias);
    if (!isIdentityProviderValid(idpModel, providerAlias)) {
      log.warnf("getValidatedIdentityProvider:: IdentityProviderModel %s is not valid",
        providerAlias);
      return null;
    }

    IdentityProviderFactory<IdentityProvider<?>> idpFactory = getIdentityProviderFactory(context, idpModel);
    if (idpFactory == null) {
      log.warnf("getValidatedIdentityProvider:: IdentityProviderFactory for %s not found",
        providerAlias);
      return null;
    }

    return idpFactory.create(context.getSession(), idpModel);
  }

  private static boolean isIdentityProviderValid(IdentityProviderModel idpModel, String providerAlias) {
    if (idpModel == null) {
      log.warnf("isIdentityProviderValid:: Identity Provider %s not found", providerAlias);
      return false;
    }
    if (!idpModel.isEnabled()) {
      log.warnf("isIdentityProviderValid:: Identity Provider %s is disabled", providerAlias);
      return false;
    }
    if (Boolean.TRUE.equals(idpModel.isLinkOnly())) {
      log.warnf("isIdentityProviderValid:: Identity Provider %s is not allowed to perform a login", providerAlias);
      return false;
    }
    return true;
  }

  @SuppressWarnings("unchecked")
  private IdentityProviderFactory<IdentityProvider<?>> getIdentityProviderFactory(AuthenticationFlowContext context,
                                                                                  IdentityProviderModel idpModel) {
    Object idpFactory = context.getSession()
      .getKeycloakSessionFactory()
      .getProviderFactory(IdentityProvider.class, idpModel.getProviderId());
    return (IdentityProviderFactory<IdentityProvider<?>>) idpFactory;
  }

  private boolean authenticateWithOidcProvider(AuthenticationFlowContext context, OIDCIdentityProvider oidcIdp,
                                               FederatedIdentityModel federatedIdentityModel) {
    OIDCIdentityProviderConfig config = oidcIdp.getConfig();

    String tokenUrl = config.getTokenUrl();
    String clientId = config.getClientId();
    String clientSecret = config.getClientSecret();

    String username = federatedIdentityModel.getUserName();
    String password = context.getHttpRequest()
      .getDecodedFormParameters()
      .getFirst(CredentialRepresentation.PASSWORD);
    try {
      String responseString = sendTokenRequest(tokenUrl, clientId, clientSecret, username, password, context);
      return processTokenResponse(context, responseString);
    } catch (Exception e) {
      log.error("Error during authentication with external IdP", e);
      return false;
    }
  }

  private String sendTokenRequest(String tokenUrl, String clientId, String clientSecret, String username,
                                  String password, AuthenticationFlowContext context)
    throws AuthenticationException, IOException {
    List<NameValuePair> params = buildTokenRequestParams(clientId, clientSecret, username, password);
    HttpPost post = new HttpPost(tokenUrl);
    post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

    HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
    HttpResponse response = httpClient.execute(post);

    int statusCode = response.getStatusLine().getStatusCode();
    String responseString = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

    if (statusCode != HttpStatus.SC_OK) {
      log.warnf("sendTokenRequest:: Authentication failed: status code %s", statusCode);
      throw new AuthenticationException("Invalid response from token endpoint: HTTP: " + statusCode);
    }
    return responseString;
  }

  private List<NameValuePair> buildTokenRequestParams(String clientId, String clientSecret, String username,
                                                      String password) {
    List<NameValuePair> params = new ArrayList<>();
    params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));
    params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, clientId));
    if (clientSecret != null && !clientSecret.isEmpty()) {
      params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, clientSecret));
    }
    params.add(new BasicNameValuePair("username", username));
    params.add(new BasicNameValuePair("password", password));
    return params;
  }

  private boolean processTokenResponse(AuthenticationFlowContext context, String responseString)
    throws JsonProcessingException {
    ObjectMapper mapper = new ObjectMapper();
    JsonNode jsonNode = mapper.readTree(responseString);
    if (jsonNode.has("access_token")) {
      context.getAuthenticationSession().setAuthNote(AuthenticationManager.PASSWORD_VALIDATED, "true");
      return true;
    } else {
      log.warnf("processTokenResponse:: Authentication failed: no access_token in response");
      return false;
    }
  }
}
