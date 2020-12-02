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

import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import java.time.Duration;
import java.time.Instant;

/**
 * Tests for {@link OAuth2TokenIntrospectionAuthenticationToken}.
 *
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionAuthenticationTokenTests {
	private String tokenValue = "tokenValue";
	private String clientId = "clientId";
	private OAuth2ClientAuthenticationToken clientPrincipal = new OAuth2ClientAuthenticationToken(
			TestRegisteredClients.registeredClient().build());
	private String tokenTypeHint = TokenType.ACCESS_TOKEN.getValue();
	private OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, this.tokenValue,
			Instant.now(), Instant.now().plus(Duration.ofHours(1)));

	@Test
	public void constructorWhenTokenValueNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionAuthenticationToken(null, this.clientPrincipal, this.tokenTypeHint))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("token cannot be empty");
	}

	@Test
	public void constructorWhenClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionAuthenticationToken(this.tokenValue, null, this.tokenTypeHint))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenTokenAndClientPrincipalNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionAuthenticationToken(null, this.clientId, this.accessToken))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("clientPrincipal cannot be null");
	}

	@Test
	public void constructorWhenTokenAndClientIdEmptyThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> new OAuth2TokenIntrospectionAuthenticationToken(this.clientPrincipal, "", this.accessToken))
				.isInstanceOf(IllegalArgumentException.class).hasMessage("clientId cannot be empty");
	}

	@Test
	public void constructorWhenTokenValueProvidedThenCreated() {
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				this.tokenValue, this.clientPrincipal, this.tokenTypeHint);
		assertThat(authentication.getTokenValue()).isEqualTo(this.tokenValue);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getTokenTypeHint()).isEqualTo(this.tokenTypeHint);
		assertThat(authentication.getToken()).isNull();
		assertThat(authentication.getClientId()).isNull();
		assertThat(authentication.isTokenActive()).isFalse();
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	public void constructorWhenTokenProvidedThenCreated() {
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				this.clientPrincipal, this.clientId, this.accessToken);
		assertThat(authentication.getToken()).isEqualTo(this.accessToken);
		assertThat(authentication.getTokenValue()).isEqualTo(this.tokenValue);
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getClientId()).isEqualTo(this.clientId);
		assertThat(authentication.isTokenActive()).isTrue();
		assertThat(authentication.getTokenTypeHint()).isNull();
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.isAuthenticated()).isTrue();
	}

	@Test
	public void constructorWhenNullTokenProvidedThenCreatedAsTokenNotActive() {
		OAuth2TokenIntrospectionAuthenticationToken authentication = new OAuth2TokenIntrospectionAuthenticationToken(
				this.clientPrincipal, this.clientId, null);
		assertThat(authentication.getToken()).isNull();
		assertThat(authentication.getTokenValue()).isNull();
		assertThat(authentication.getPrincipal()).isEqualTo(this.clientPrincipal);
		assertThat(authentication.getClientId()).isEqualTo(this.clientId);
		assertThat(authentication.isTokenActive()).isFalse();
		assertThat(authentication.getTokenTypeHint()).isNull();
		assertThat(authentication.getCredentials().toString()).isEmpty();
		assertThat(authentication.isAuthenticated()).isTrue();
	}
}
