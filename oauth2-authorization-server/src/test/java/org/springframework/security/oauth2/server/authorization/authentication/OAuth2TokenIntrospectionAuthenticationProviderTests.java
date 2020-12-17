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
package org.springframework.security.oauth2.server.authorization.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes2;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;

/**
 * Tests for {@link OAuth2TokenIntrospectionAuthenticationProvider}.
 *
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionAuthenticationProviderTests {
	private OAuth2AuthorizationService authorizationService;
	private OAuth2TokenIntrospectionAuthenticationProvider authenticationProvider;
	private JwtDecoder jwtDecoder;

	@Before
	public void setUp() {
		this.authorizationService = mock(OAuth2AuthorizationService.class);
		this.jwtDecoder = mock(JwtDecoder.class);
		this.authenticationProvider = new OAuth2TokenIntrospectionAuthenticationProvider(
				this.authorizationService, Collections.singletonList(this.jwtDecoder));
	}

	@Test
	public void constructorWhenAuthorizationServiceNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(
				() -> new OAuth2TokenIntrospectionAuthenticationProvider(
						null, Collections.singletonList(this.jwtDecoder))).isInstanceOf(IllegalArgumentException.class)
								.hasMessage("authorizationService cannot be null");
	}

	@Test
	public void supportsWhenTypeOAuth2TokenIntrospectionAuthenticationTokenThenReturnTrue() {
		assertThat(this.authenticationProvider.supports(OAuth2TokenIntrospectionAuthenticationToken.class)).isTrue();
	}

	@Test
	public void authenticateWhenClientPrincipalNotOAuth2ClientAuthenticationTokenThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		TestingAuthenticationToken clientPrincipal = new TestingAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret());
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, TokenType.ACCESS_TOKEN.getValue());
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenClientPrincipalNotAuthenticatedThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
				registeredClient.getClientId(), registeredClient.getClientSecret(), ClientAuthenticationMethod.BASIC,
				null);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, TokenType.ACCESS_TOKEN.getValue());
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	@Test
	public void authenticateWhenInvalidTokenTypeThenThrowOAuth2AuthenticationException() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, OAuth2ErrorCodes2.UNSUPPORTED_TOKEN_TYPE);
		assertThatThrownBy(() -> this.authenticationProvider.authenticate(authentication))
				.isInstanceOf(OAuth2AuthenticationException.class)
				.extracting(ex -> ((OAuth2AuthenticationException) ex).getError()).extracting("errorCode")
				.isEqualTo(OAuth2ErrorCodes2.UNSUPPORTED_TOKEN_TYPE);
	}

	@Test
	public void authenticateWhenTokenNotFoundThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, TokenType.ACCESS_TOKEN.getValue());
		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
	}

	@Test
	public void authenticateWhenTokenIssuedToAnotherClientThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(TestRegisteredClients.registeredClient2().build()).build();
		when(this.authorizationService.findByToken(eq("token"), eq(TokenType.ACCESS_TOKEN))).thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				"token", clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
	}

	@Test
	public void authenticateWhenInvalidatedTokenThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken accessToken = authorization.getTokens().getAccessToken();
		authorization = OAuth2AuthenticationProviderUtils.invalidate(authorization, accessToken);
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
	}

	@Test
	public void authenticateWhenValidTokenThenActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken accessToken = authorization.getTokens().getAccessToken();
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		when(this.jwtDecoder.decode(eq(accessToken.getTokenValue()))).thenThrow(JwtException.class);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isTrue();
		assertThat(authenticationResult.getToken()).isSameAs(accessToken);
	}

	@Test
	public void authenticateWhenExpiredTokenThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		Instant expiresAt = Instant.now().minus(Duration.ofHours(1));
		Instant issuedAt = expiresAt.minus(Duration.ofHours(1));
		OAuth2AccessToken accessToken = new OAuth2AccessToken(
				OAuth2AccessToken.TokenType.BEARER, "access-token", issuedAt, expiresAt);
		OAuth2Tokens tokens = OAuth2Tokens.builder().accessToken(accessToken).build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).tokens(tokens)
				.build();
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		when(this.jwtDecoder.decode(eq(accessToken.getTokenValue()))).thenThrow(JwtException.class);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
		assertThat(authenticationResult.getToken()).isNull();
	}

	@Test
	public void authenticateWhenValidJwtThenTokenActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken accessToken = authorization.getTokens().getAccessToken();
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		Jwt jwt = Jwt.withTokenValue(accessToken.getTokenValue()).header("customHeader", "customHeaderValue")
				.expiresAt(accessToken.getExpiresAt()).issuedAt(accessToken.getIssuedAt())
				.notBefore(accessToken.getIssuedAt()).build();
		when(this.jwtDecoder.decode(eq(accessToken.getTokenValue()))).thenReturn(jwt);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isTrue();
		assertThat(authenticationResult.getToken()).isSameAs(jwt);
	}

	@Test
	public void authenticateWhenExpiredJwtThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken accessToken = authorization.getTokens().getAccessToken();
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		Instant expiresAt = Instant.now().minus(Duration.ofHours(1));
		Instant issuedAt = expiresAt.minus(Duration.ofHours(1));
		Jwt jwt = Jwt.withTokenValue(accessToken.getTokenValue()).header("customHeader", "customHeaderValue")
				.expiresAt(expiresAt).issuedAt(issuedAt).notBefore(issuedAt).build();
		when(this.jwtDecoder.decode(eq(accessToken.getTokenValue()))).thenReturn(jwt);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
		assertThat(authenticationResult.getToken()).isNull();
	}

	@Test
	public void authenticateWhenInvalidNotBeforeJwtThenAuthenticatedButTokenNotActive() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken accessToken = authorization.getTokens().getAccessToken();
		when(this.authorizationService.findByToken(eq(accessToken.getTokenValue()), eq(TokenType.ACCESS_TOKEN)))
				.thenReturn(authorization);
		Jwt jwt = Jwt.withTokenValue(accessToken.getTokenValue()).header("customHeader", "customHeaderValue")
				.expiresAt(accessToken.getExpiresAt()).issuedAt(accessToken.getIssuedAt())
				.notBefore(accessToken.getExpiresAt()).build();
		when(this.jwtDecoder.decode(eq(accessToken.getTokenValue()))).thenReturn(jwt);

		OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(registeredClient);
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				accessToken.getTokenValue(), clientPrincipal, TokenType.ACCESS_TOKEN.getValue());

		OAuth2TokenIntrospectionAuthenticationToken authenticationResult = (OAuth2TokenIntrospectionAuthenticationToken) this.authenticationProvider
				.authenticate(authentication);
		assertThat(authenticationResult.isAuthenticated()).isTrue();
		assertThat(authenticationResult.isTokenActive()).isFalse();
		assertThat(authenticationResult.getToken()).isNull();
	}
}
