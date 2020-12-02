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
package org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization;

import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.matchesPattern;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.crypto.key.CryptoKeySource;
import org.springframework.security.crypto.key.StaticKeyGeneratingCryptoKeySource;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.jose.jws.NimbusJwsEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TestOAuth2Authorizations;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import com.nimbusds.oauth2.sdk.token.AccessTokenType;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;

/**
 * Integration tests for the OAuth 2.0 Token Introspection endpoint.
 *
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionTests {

	private static final String URL_PATTERN_REGEX = "^(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";
	private static RegisteredClientRepository registeredClientRepository;
	private static OAuth2AuthorizationService authorizationService;
	private static CryptoKeySource keySource;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@BeforeClass
	public static void init() {
		registeredClientRepository = mock(RegisteredClientRepository.class);
		authorizationService = mock(OAuth2AuthorizationService.class);
		keySource = new StaticKeyGeneratingCryptoKeySource();
	}

	@Before
	public void setup() {
		reset(registeredClientRepository);
		reset(authorizationService);
	}

	@Test
	public void requestWhenIntrospectValidRefreshTokenThenActiveResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2RefreshToken token = authorization.getTokens().getRefreshToken();
		TokenType tokenType = TokenType.REFRESH_TOKEN;
		when(authorizationService.findByTokenWithHint(eq(token.getTokenValue()), eq(Optional.of(tokenType))))
				.thenReturn(Optional.of(authorization));

		// @formatter:off
		this.mvc.perform(
				MockMvcRequestBuilders.post(OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI)
						.params(getTokenIntrospectionRequestParameters(token, tokenType))
						.with(httpBasic(registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.active", is(true)))
				.andExpect(jsonPath("$.client_id", is("client-1")))
				.andExpect(jsonPath("$.iat", lessThanOrEqualTo(Instant.now().getEpochSecond()), Long.class))
				.andExpect(jsonPath("$.exp", greaterThanOrEqualTo(Instant.now().getEpochSecond()), Long.class));
		// @formatter:on

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByTokenWithHint(eq(token.getTokenValue()), eq(Optional.of(tokenType)));
	}

	@Test
	public void requestWhenIntrospectValidAccessTokenThenActiveResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations.authorization(registeredClient).build();
		OAuth2AccessToken token = authorization.getTokens().getAccessToken();
		TokenType tokenType = TokenType.ACCESS_TOKEN;
		when(authorizationService.findByTokenWithHint(eq(token.getTokenValue()), eq(Optional.of(tokenType))))
				.thenReturn(Optional.of(authorization));

		// @formatter:off
		this.mvc.perform(
				MockMvcRequestBuilders.post(OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI)
						.params(getTokenIntrospectionRequestParameters(token, tokenType))
						.with(httpBasic(registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.active", is(true)))
				.andExpect(jsonPath("$.client_id", is("client-1")))
				.andExpect(jsonPath("$.scope", allOf(containsString("openid"), containsString("profile"), containsString("email"))))
				.andExpect(jsonPath("$.token_type", is(AccessTokenType.BEARER.getValue())))
				.andExpect(jsonPath("$.iat", lessThanOrEqualTo(Instant.now().getEpochSecond()), Long.class))
				.andExpect(jsonPath("$.exp", greaterThanOrEqualTo(Instant.now().getEpochSecond()), Long.class));
		// @formatter:on

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByTokenWithHint(eq(token.getTokenValue()), eq(Optional.of(tokenType)));
	}

	@Test
	public void requestWhenIntrospectValidJwtAccessTokenThenActiveResponse() throws Exception {
		this.spring.register(AuthorizationServerConfiguration.class).autowire();

		JwtEncoder jwtEncoder = new NimbusJwsEncoder(this.spring.getContext().getBean(CryptoKeySource.class));

		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();
		when(registeredClientRepository.findByClientId(eq(registeredClient.getClientId())))
				.thenReturn(registeredClient);

		OAuth2Authorization authorization = TestOAuth2Authorizations
				.authorization(registeredClient, Collections.emptyMap(), jwtEncoder).build();
		OAuth2AccessToken token = authorization.getTokens().getAccessToken();
		TokenType tokenType = TokenType.ACCESS_TOKEN;
		when(authorizationService.findByTokenWithHint(eq(token.getTokenValue()), eq(Optional.of(tokenType))))
				.thenReturn(Optional.of(authorization));

		// @formatter:off
		this.mvc.perform(
				MockMvcRequestBuilders.post(OAuth2TokenIntrospectionEndpointFilter.DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI)
						.params(getTokenIntrospectionRequestParameters(token, tokenType))
						.with(httpBasic(registeredClient.getClientId(), registeredClient.getClientSecret())))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.active", is(true)))
				.andExpect(jsonPath("$.scope", allOf(containsString("openid"), containsString("profile"), containsString("email"))))
				.andExpect(jsonPath("$.sub", is("user-1")))
				.andExpect(jsonPath("$.aud", contains("client-1")))
				.andExpect(jsonPath("$.iss", matchesPattern(URL_PATTERN_REGEX)))
				.andExpect(jsonPath("$.token_type", is(AccessTokenType.BEARER.getValue())))
				.andExpect(jsonPath("$.client_id").isString())
				.andExpect(jsonPath("$.iat", lessThanOrEqualTo(Instant.now().getEpochSecond()), Long.class))
				.andExpect(jsonPath("$.nbf", lessThanOrEqualTo(Instant.now().getEpochSecond()), Long.class))
				.andExpect(jsonPath("$.exp", greaterThanOrEqualTo(Instant.now().getEpochSecond()), Long.class));
		// @formatter:on

		verify(registeredClientRepository).findByClientId(eq(registeredClient.getClientId()));
		verify(authorizationService).findByTokenWithHint(eq(token.getTokenValue()), eq(Optional.of(tokenType)));
	}

	private static MultiValueMap<String, String> getTokenIntrospectionRequestParameters(AbstractOAuth2Token token,
			TokenType tokenType) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames2.TOKEN, token.getTokenValue());
		parameters.set(OAuth2ParameterNames2.TOKEN_TYPE_HINT, tokenType.getValue());
		return parameters;
	}

	@EnableWebSecurity
	@Import(OAuth2AuthorizationServerConfiguration.class)
	static class AuthorizationServerConfiguration {

		@Bean
		RegisteredClientRepository registeredClientRepository() {
			return registeredClientRepository;
		}

		@Bean
		OAuth2AuthorizationService authorizationService() {
			return authorizationService;
		}

		@Bean
		CryptoKeySource keySource() {
			return keySource;
		}
	}
}
