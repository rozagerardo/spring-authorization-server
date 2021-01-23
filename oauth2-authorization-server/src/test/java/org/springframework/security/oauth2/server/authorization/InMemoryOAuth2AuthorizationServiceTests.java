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
package org.springframework.security.oauth2.server.authorization;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link InMemoryOAuth2AuthorizationService}.
 *
 * @author Krisztian Toth
 * @author Joe Grandja
 * @author Gerardo Roza
 */
public class InMemoryOAuth2AuthorizationServiceTests {
	private static final RegisteredClient REGISTERED_CLIENT = TestRegisteredClients.registeredClient().build();
	private static final String PRINCIPAL_NAME = "principal";
	private static final OAuth2AuthorizationCode AUTHORIZATION_CODE = new OAuth2AuthorizationCode(
			"code", Instant.now(), Instant.now().plus(5, ChronoUnit.MINUTES));
	private InMemoryOAuth2AuthorizationService authorizationService;

	@Before
	public void setup() {
		this.authorizationService = new InMemoryOAuth2AuthorizationService();
	}

	@Test
	public void saveWhenAuthorizationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.save(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorization cannot be null");
	}

	@Test
	public void saveWhenAuthorizationProvidedThenSaved() {
		OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.tokens(OAuth2Tokens.builder().token(AUTHORIZATION_CODE).build())
				.build();
		this.authorizationService.save(expectedAuthorization);

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				AUTHORIZATION_CODE.getTokenValue(), TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isEqualTo(expectedAuthorization);
	}

	@Test
	public void removeWhenAuthorizationNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.remove(null))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("authorization cannot be null");
	}

	@Test
	public void removeWhenAuthorizationProvidedThenRemoved() {
		OAuth2Authorization expectedAuthorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.tokens(OAuth2Tokens.builder().token(AUTHORIZATION_CODE).build())
				.build();

		this.authorizationService.save(expectedAuthorization);
		OAuth2Authorization authorization = this.authorizationService.findByToken(
				AUTHORIZATION_CODE.getTokenValue(), TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isEqualTo(expectedAuthorization);

		this.authorizationService.remove(expectedAuthorization);
		authorization = this.authorizationService.findByToken(
				AUTHORIZATION_CODE.getTokenValue(), TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isNull();
	}

	@Test
	public void findByTokenWhenTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> this.authorizationService.findByToken(null, TokenType.AUTHORIZATION_CODE))
				.isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be empty");
	}

	@Test
	public void findByTokenWhenStateExistsThenFound() {
		String state = "state";
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.attribute(OAuth2AuthorizationAttributeNames.STATE, state)
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				state, new TokenType(OAuth2AuthorizationAttributeNames.STATE));
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(state, null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenAuthorizationCodeExistsThenFound() {
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.tokens(OAuth2Tokens.builder().token(AUTHORIZATION_CODE).build())
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				AUTHORIZATION_CODE.getTokenValue(), TokenType.AUTHORIZATION_CODE);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(AUTHORIZATION_CODE.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenAccessTokenExistsThenFound() {
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				"access-token", Instant.now().minusSeconds(60), Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.tokens(OAuth2Tokens.builder().token(AUTHORIZATION_CODE).accessToken(accessToken).build())
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				accessToken.getTokenValue(), TokenType.ACCESS_TOKEN);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(accessToken.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenRefreshTokenExistsThenFound() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.tokens(OAuth2Tokens.builder().refreshToken(refreshToken).build())
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				refreshToken.getTokenValue(), TokenType.REFRESH_TOKEN);
		assertThat(authorization).isEqualTo(result);
		result = this.authorizationService.findByToken(refreshToken.getTokenValue(), null);
		assertThat(authorization).isEqualTo(result);
	}

	@Test
	public void findByTokenWhenWrongTokenTypeThenNotFound() {
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken("refresh-token", Instant.now());
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(REGISTERED_CLIENT)
				.principalName(PRINCIPAL_NAME)
				.tokens(OAuth2Tokens.builder().refreshToken(refreshToken).build())
				.build();
		this.authorizationService.save(authorization);

		OAuth2Authorization result = this.authorizationService.findByToken(
				refreshToken.getTokenValue(), TokenType.ACCESS_TOKEN);
		assertThat(result).isNull();
	}

	@Test
	public void findByTokenWhenTokenDoesNotExistThenNull() {
		OAuth2Authorization result = this.authorizationService.findByToken(
				"access-token", TokenType.ACCESS_TOKEN);
		assertThat(result).isNull();
	}
}
