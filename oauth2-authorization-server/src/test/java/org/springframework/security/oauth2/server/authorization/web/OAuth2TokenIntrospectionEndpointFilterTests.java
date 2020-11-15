/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.web;

import static java.lang.Math.toIntExact;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.assertj.core.api.Condition;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenMetadata;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter.NimbusTokenIntrospectionResponseHttpMessageConverter;

import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;

import net.minidev.json.JSONObject;

/**
 * Tests for {@link OAuth2TokenIntrospectionEndpointFilter}.
 *
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionEndpointFilterTests {

	private OAuth2AuthorizationService authorizationService;
	private OAuth2TokenIntrospectionEndpointFilter filter;
	private final JwtDecoder decoder = mock(JwtDecoder.class);
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();
	private final HttpMessageConverter<TokenIntrospectionSuccessResponse> tokenIntrospectionHttpResponseConverter = new NimbusTokenIntrospectionResponseHttpMessageConverter();
	private final Condition<Object> scopesMatchesInAnyOrder = new Condition<>(
			scopes -> scopes.equals("scope1 Scope2") || scopes.equals("Scope2 scope1"), "scopes match");

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.filter = new OAuth2TokenIntrospectionEndpointFilter(authorizationService, Collections.singletonList(decoder));
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionEndpointFilter(null, Collections.singletonList(this.decoder)))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("authorizationService cannot be null");
	}

	@Test
	public void constructorWhenTokenEndpointUriNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionEndpointFilter(this.authorizationService,
				Collections.singletonList(this.decoder), null)).isInstanceOf(IllegalArgumentException.class)
						.hasMessage("tokenIntrospectionEndpointUri cannot be empty");
	}

	@Test
	public void doFilterWhenNotIntrospectionRequestThenNotProcessed() throws Exception {
		String requestUri = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenIntrospectionRequestGetThenNotProcessed() throws Exception {
		String requestUri = OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		this.filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenIntrospectionRequestMissingTokenParamThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		request.removeParameter(OAuth2ParameterNames.TOKEN);

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(OAuth2ParameterNames.TOKEN,
				OAuth2ErrorCodes.INVALID_REQUEST, request);

	}

	@Test
	public void doFilterWhenTokenRequestMultipleTokenParamThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		request.addParameter(OAuth2ParameterNames.TOKEN, "token.456");

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(OAuth2ParameterNames.TOKEN,
				OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenTokenRequestMultipleTokenTypeHintParamThenInvalidRequestError() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		request.addParameter(OAuth2ParameterNames.TOKEN_TYPE_HINT, TokenType.REFRESH_TOKEN.getValue());

		doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(OAuth2ParameterNames.TOKEN_TYPE_HINT,
				OAuth2ErrorCodes.INVALID_REQUEST, request);
	}

	@Test
	public void doFilterWhenIntrospectNonExistingTokenThenNotActiveTokenOkReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		setupSecurityContext();

		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue())))
				.thenReturn(null);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertNotActiveTokenResponse(response);
	}

	@Test
	public void doFilterWhenIntrospectTokenFromDifferentClientThenNotActiveTokenOkReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue())))
				.thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn("otherClientId");

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertNotActiveTokenResponse(response);
	}

	@Test
	public void doFilterWhenIntrospectExpiredTokenThenNotActiveTokenOkReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue())))
				.thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getClientId());

		Instant issuedAt = Instant.now().minus(Duration.ofHours(2));
		retrieveOAuth2AccessToken(tokenAuthorization, issuedAt, false);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertNotActiveTokenResponse(response);
	}

	@Test
	public void doFilterWhenIntrospectInvalidatedTokenThenNotActiveTokenOkReponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue())))
				.thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getId());

		Instant issuedAt = Instant.now();
		retrieveOAuth2AccessToken(tokenAuthorization, issuedAt, true);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertNotActiveTokenResponse(response);
	}

	@Test
	public void doFilterWhenIntrospectValidAccessTokenThenValidTokenResponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue())))
				.thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getId());

		Instant issuedAt = Instant.now();
		retrieveOAuth2AccessToken(tokenAuthorization, issuedAt, false);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		TokenIntrospectionSuccessResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		JSONObject jsonResponseObject = tokenIntrospectionResponse.toJSONObject();
		// @formatter:off
		assertThat(jsonResponseObject).contains(
				entry("active", true),
				entry("client_id", registeredClient.getClientId()),
				entry(OAuth2ParameterNames.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue()),
				entry(JwtClaimNames.EXP, Integer.valueOf(toIntExact(issuedAt.plus(Duration.ofHours(1)).getEpochSecond()))),
				entry(JwtClaimNames.IAT, Integer.valueOf(toIntExact(issuedAt.getEpochSecond()))))
		.hasEntrySatisfying(OAuth2ParameterNames.SCOPE, scopesMatchesInAnyOrder)
		.hasSize(6);
		// @formatter: on
	}
	
	@Test
	public void doFilterWhenIntrospectValidRefreshTokenThenValidTokenResponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue())))
				.thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getId());

		Instant issuedAt = Instant.now();
		retrieveOAuth2RefreshToken(tokenAuthorization, issuedAt, false);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		TokenIntrospectionSuccessResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		JSONObject jsonResponseObject = tokenIntrospectionResponse.toJSONObject();
		// @formatter:off
		assertThat(jsonResponseObject).containsOnly(
				entry("active", true),
				entry("client_id", registeredClient.getClientId()),
				entry(JwtClaimNames.EXP, Integer.valueOf(toIntExact(issuedAt.plus(Duration.ofHours(1)).getEpochSecond()))),
				entry(JwtClaimNames.IAT, Integer.valueOf(toIntExact(issuedAt.getEpochSecond()))));
		// @formatter: on
	}
	
	@Test
	public void doFilterWhenIntrospectValidJwtTokenThenValidTokenResponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue()))).thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getId());

		retrieveAbstractOAuth2Token(tokenAuthorization);
		Instant issuedAt = Instant.now();
		
		Jwt jwt = createJwt(issuedAt).claim("customClaim", "customValue").build();
		when(this.decoder.decode("token.123")).thenReturn(jwt);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		TokenIntrospectionSuccessResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		JSONObject jsonResponseObject = tokenIntrospectionResponse.toJSONObject();
		// @formatter:off
		assertThat(jsonResponseObject).contains(
				entry("active", true),
				entry("client_id", registeredClient.getClientId()),
				entry(OAuth2ParameterNames.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue()),
				entry(JwtClaimNames.EXP, Integer.valueOf(toIntExact(issuedAt.plus(Duration.ofHours(1)).getEpochSecond()))),
				entry(JwtClaimNames.IAT, Integer.valueOf(toIntExact(issuedAt.getEpochSecond()))),
				entry(JwtClaimNames.NBF, Integer.valueOf(toIntExact(issuedAt.getEpochSecond()))),
				entry(JwtClaimNames.AUD, Collections.singletonList("audience1")),
				entry(JwtClaimNames.ISS, "http://issuer1.com"),
				entry(JwtClaimNames.JTI, "jti1"),
				entry(JwtClaimNames.SUB, "subject1"))
		.hasEntrySatisfying(OAuth2ParameterNames.SCOPE, scopesMatchesInAnyOrder)
		.hasSize(11);
		// @formatter: on
	}
	
	/**
	 * Test for {@code Jwt} created with the minimum required fields according to the access_token and id_token specifications.
	 * 
	 * @see <a target="_blank" href="https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10">JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens</a> 
	 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core - ID Token</a>
	 * 
	 * @throws Exception
	 */
	@Test
	public void doFilterWhenIntrospectValidJwtWithMinimumExpectedDataThenValidTokenResponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		
		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue()))).thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getId());
		
		retrieveAbstractOAuth2Token(tokenAuthorization);
		Instant issuedAt = Instant.now();
		
		Jwt jwt = Jwt.withTokenValue("token.123").header("customHeader", "customHeaderValue").audience(Collections.singletonList("audience1")).expiresAt(issuedAt.plus(Duration.ofHours(1))).issuedAt(issuedAt).issuer("http://issuer1.com").subject("subject1").build();
		when(this.decoder.decode("token.123")).thenReturn(jwt);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		TokenIntrospectionSuccessResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		JSONObject jsonResponseObject = tokenIntrospectionResponse.toJSONObject();
		// @formatter:off
		assertThat(jsonResponseObject).containsOnly(entry("active", true),
				entry("client_id", registeredClient.getClientId()),
				entry(OAuth2ParameterNames.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue()),
				entry(JwtClaimNames.EXP, Integer.valueOf(toIntExact(issuedAt.plus(Duration.ofHours(1)).getEpochSecond()))),
				entry(JwtClaimNames.IAT, Integer.valueOf(toIntExact(issuedAt.getEpochSecond()))),
				entry(JwtClaimNames.AUD, Collections.singletonList("audience1")),
				entry(JwtClaimNames.ISS, "http://issuer1.com"),
				entry(JwtClaimNames.SUB, "subject1"));
		// @formatter: on
	}
	
	@Test
	public void doFilterWhenIntrospectValidJwtWithNoExpirationDataThenValidTokenResponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		
		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue()))).thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getId());
		
		retrieveAbstractOAuth2Token(tokenAuthorization);
		
		Jwt jwt = Jwt.withTokenValue("token.123").header("customHeader", "customHeaderValue").claim("customClaim", "customClaimValue").build();
		when(this.decoder.decode("token.123")).thenReturn(jwt);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		TokenIntrospectionSuccessResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		JSONObject jsonResponseObject = tokenIntrospectionResponse.toJSONObject();
		// @formatter:off
		assertThat(jsonResponseObject).containsOnly(entry("active", true),
				entry("client_id", registeredClient.getClientId()),
				entry(OAuth2ParameterNames.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue()));
		// @formatter: on
	}
	
	@Test
	public void doFilterWhenIntrospectAccessTokenWithMinimumDataThenValidTokenResponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue())))
				.thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getId());

		OAuth2Tokens tokens = mock(OAuth2Tokens.class);
		when(tokenAuthorization.getTokens()).thenReturn(tokens);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token.123", null,
				null);
		when(tokens.getToken("token.123", Optional.of(new TokenType(TokenType.ACCESS_TOKEN.getValue()))))
				.thenReturn(Optional.of(accessToken));
		OAuth2TokenMetadata metadata = mock(OAuth2TokenMetadata.class);
		when(tokens.getTokenMetadata(accessToken)).thenReturn(metadata);
		when(metadata.isInvalidated()).thenReturn(false);
		when(this.decoder.decode("token.123")).thenThrow(JwtException.class);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		TokenIntrospectionSuccessResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);

		JSONObject jsonResponseObject = tokenIntrospectionResponse.toJSONObject();
		// @formatter:off
		assertThat(jsonResponseObject).containsOnly(
				entry("active", true),
				entry("client_id", registeredClient.getClientId()),
				entry(OAuth2ParameterNames.TOKEN_TYPE, OAuth2AccessToken.TokenType.BEARER.getValue()));
		// @formatter: on
	}
	
	@Test
	public void doFilterWhenIntrospectExpiredJwtTokenThenNotValidTokenResponse() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", TokenType.ACCESS_TOKEN.getValue());
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		RegisteredClient registeredClient = setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue()))).thenReturn(tokenAuthorization);

		when(tokenAuthorization.getRegisteredClientId()).thenReturn(registeredClient.getId());

		retrieveAbstractOAuth2Token(tokenAuthorization);
		Instant issuedAt = Instant.now().minus(Duration.ofHours(2));
		
		Jwt jwt = createJwt(issuedAt).claim("customClaim", "customValue").build();
		when(this.decoder.decode("token.123")).thenReturn(jwt);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertNotActiveTokenResponse(response);
	}
	
	@Test
	public void doFilterWhenIntrospectWithoutTokenTypeHintParamThenTokenSearchedWithAllSupportedTokenTypes() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", null);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		
		setupSecurityContext();

		when(this.authorizationService.findByToken(any(String.class), any(TokenType.class)))
				.thenReturn(null);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		verify(authorizationService).findByToken("token.123", new TokenType(TokenType.ACCESS_TOKEN.getValue()));
		verify(authorizationService).findByToken("token.123", new TokenType(TokenType.REFRESH_TOKEN.getValue()));

		assertNotActiveTokenResponse(response);
	}
	
	@Test
	public void doFilterWhenIntrospectWithAccessTokenHintThenTokenSearchedWithAccessTokenFirst() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", "access_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		
		setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken(any(String.class), any(TokenType.class)))
				.thenReturn(tokenAuthorization);
		when(tokenAuthorization.getRegisteredClientId()).thenReturn("otherClientId");

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		
		ArgumentCaptor<TokenType> tokenTypeCaptor =
				ArgumentCaptor.forClass(TokenType.class);
		verify(this.authorizationService).findByToken(any(String.class), tokenTypeCaptor.capture());
		TokenType tokenType =
				tokenTypeCaptor.getValue();
		assertThat(tokenType).isEqualTo(TokenType.ACCESS_TOKEN);
	}
	
	@Test
	public void doFilterWhenIntrospectWithRefreshTokenHintThenTokenSearchedWithRefreshTokenFirst() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", "refresh_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		
		setupSecurityContext();

		OAuth2Authorization tokenAuthorization = mock(OAuth2Authorization.class);
		when(this.authorizationService.findByToken(any(String.class), any(TokenType.class)))
				.thenReturn(tokenAuthorization);
		when(tokenAuthorization.getRegisteredClientId()).thenReturn("otherClientId");

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		
		ArgumentCaptor<TokenType> tokenTypeCaptor =
				ArgumentCaptor.forClass(TokenType.class);
		verify(this.authorizationService).findByToken(any(String.class), tokenTypeCaptor.capture());
		TokenType tokenType =
				tokenTypeCaptor.getValue();
		assertThat(tokenType).isEqualTo(TokenType.REFRESH_TOKEN);
	}
	
	@Test
	public void doFilterWhenIntrospectWithUnknownTokenHintThenTokenSearchedAnyway() throws Exception {
		MockHttpServletRequest request = createTokenIntrospectionRequest("token.123", "unknown_token");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);
		
		setupSecurityContext();

		when(this.authorizationService.findByToken(any(String.class), any(TokenType.class)))
				.thenReturn(null);

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);
		
		verify(this.authorizationService, times(2)).findByToken(any(String.class), any(TokenType.class));
	}

	private void assertNotActiveTokenResponse(MockHttpServletResponse response) throws Exception {
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		TokenIntrospectionSuccessResponse tokenIntrospectionResponse = readTokenIntrospectionResponse(response);
		assertThat(tokenIntrospectionResponse.toJSONObject()).containsEntry("active", false).hasSize(1);
	}

	private OAuth2Error readError(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.errorHttpResponseConverter.read(OAuth2Error.class, httpResponse);
	}

	private TokenIntrospectionSuccessResponse readTokenIntrospectionResponse(MockHttpServletResponse response) throws Exception {
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(response.getContentAsByteArray(),
				HttpStatus.valueOf(response.getStatus()));
		return this.tokenIntrospectionHttpResponseConverter.read(TokenIntrospectionSuccessResponse.class, httpResponse);
	}

	private void doFilterWhenTokenIntrospectionRequestInvalidParameterThenError(String parameterName, String errorCode,
			MockHttpServletRequest request) throws Exception {

		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		setupSecurityContext();

		this.filter.doFilter(request, response, filterChain);

		verifyNoInteractions(filterChain);

		assertThat(response.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
		OAuth2Error error = readError(response);
		assertThat(error.getErrorCode()).isEqualTo(errorCode);
		assertThat(error.getDescription()).isEqualTo("OAuth 2.0 Token Introspection Parameter: " + parameterName);
	}
	
	private static RegisteredClient setupSecurityContext() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Authentication clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(clientPrincipal);
		SecurityContextHolder.setContext(securityContext);
		return registeredClient;
	}
	
	private AbstractOAuth2Token retrieveAbstractOAuth2Token(OAuth2Authorization tokenAuthorization) {
		OAuth2Tokens tokens = mock(OAuth2Tokens.class);
		when(tokenAuthorization.getTokens()).thenReturn(tokens);
		AbstractOAuth2Token token = mock(AbstractOAuth2Token.class);
		when(tokens.getToken("token.123", Optional.of(new TokenType(TokenType.ACCESS_TOKEN.getValue())))).thenReturn(Optional.of(token));
		when(token.getTokenValue()).thenReturn("token.123");
		OAuth2TokenMetadata metadata = mock(OAuth2TokenMetadata.class);
		when(tokens.getTokenMetadata(token)).thenReturn(metadata);
		when(metadata.isInvalidated()).thenReturn(false);
		return token;
	}
	
	/**
	 * Creates an {@code OAuth2AccessToken} with all the basic fields and with validity of one hour from the issuedAt parameter.
	 * 
	 * @param tokenAuthorization mock {@code OAuth2Authorization}
	 * @return configured {@code OAuth2AccessToken}
	 */
	private OAuth2AccessToken retrieveOAuth2AccessToken(OAuth2Authorization tokenAuthorization, Instant issuedAt, boolean invalidated) {
		OAuth2Tokens tokens = mock(OAuth2Tokens.class);
		when(tokenAuthorization.getTokens()).thenReturn(tokens);
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		Set<String> scopes = new HashSet<>(Arrays.asList("scope1", "Scope2"));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token.123", issuedAt,
				expiresAt, scopes);
		when(tokens.getToken("token.123", Optional.of(new TokenType(TokenType.ACCESS_TOKEN.getValue()))))
				.thenReturn(Optional.of(accessToken));
		OAuth2TokenMetadata metadata = mock(OAuth2TokenMetadata.class);
		when(tokens.getTokenMetadata(accessToken)).thenReturn(metadata);
		when(metadata.isInvalidated()).thenReturn(invalidated);
		when(this.decoder.decode("token.123")).thenThrow(JwtException.class);
		return accessToken;
	}
	
	/**
	 * Creates an {@code OAuth2RefreshToken} with all the basic fields and with validity of one hour from the issuedAt parameter.
	 * 
	 * @param tokenAuthorization mock {@code OAuth2Authorization}
	 * @return configured {@code OAuth2RefreshToken}
	 */
	private OAuth2RefreshToken retrieveOAuth2RefreshToken(OAuth2Authorization tokenAuthorization, Instant issuedAt, boolean invalidated) {
		OAuth2Tokens tokens = mock(OAuth2Tokens.class);
		when(tokenAuthorization.getTokens()).thenReturn(tokens);
		Instant expiresAt = issuedAt.plus(Duration.ofHours(1));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("token.123", issuedAt,
				expiresAt);
		when(tokens.getToken("token.123", Optional.of(new TokenType(TokenType.ACCESS_TOKEN.getValue()))))
				.thenReturn(Optional.of(refreshToken));
		OAuth2TokenMetadata metadata = mock(OAuth2TokenMetadata.class);
		when(tokens.getTokenMetadata(refreshToken)).thenReturn(metadata);
		when(metadata.isInvalidated()).thenReturn(invalidated);
		when(this.decoder.decode("token.123")).thenThrow(JwtException.class);
		return refreshToken;
	}
	
	/**
	 * Creates a {@code Jwt.Builder} pre-configured with all the basic fields and with validity of one hour from the issuedAt parameter.
	 * 
	 * @param issuedAt {@code Instant} indicating time at which the resulting {@code Jwt} would be issued, token will expire one hour from this point 
	 * @return a pre-configured {@code Jwt.Builder}
	 */
	private static Jwt.Builder createJwt(Instant issuedAt) {
		return Jwt.withTokenValue("token.123").header("customHeader", "customHeaderValue").audience(Collections.singletonList("audience1")).expiresAt(issuedAt.plus(Duration.ofHours(1))).issuedAt(issuedAt).notBefore(issuedAt).issuer("http://issuer1.com").jti("jti1").subject("subject1").claim(OAuth2ParameterNames.SCOPE, new HashSet<>(Arrays.asList("scope1", "Scope2")));
	}

	private static MockHttpServletRequest createTokenIntrospectionRequest(String token, String tokenTypeHint) {
		String requestUri = OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI;
		MockHttpServletRequest request = new MockHttpServletRequest("POST", requestUri);
		request.setServletPath(requestUri);

		request.addParameter(OAuth2ParameterNames.TOKEN, token);
		request.addParameter(OAuth2ParameterNames.TOKEN_TYPE_HINT, tokenTypeHint);
		return request;
	}
}