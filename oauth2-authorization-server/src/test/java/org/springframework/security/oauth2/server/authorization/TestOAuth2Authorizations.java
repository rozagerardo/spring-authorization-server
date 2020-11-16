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

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken2;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.JoseHeader;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2Tokens;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
public class TestOAuth2Authorizations {

	public static OAuth2Authorization.Builder authorization() {
		return authorization(TestRegisteredClients.registeredClient().build());
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient) {
		return authorization(registeredClient, Collections.emptyMap());
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
			Map<String, Object> authorizationRequestAdditionalParameters) {
		return authorization(registeredClient, authorizationRequestAdditionalParameters, null);
	}

	public static OAuth2Authorization.Builder authorization(RegisteredClient registeredClient,
			Map<String, Object> authorizationRequestAdditionalParameters, JwtEncoder jwtEncoder) {
		OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode("code", Instant.now(),
				Instant.now().plusSeconds(120));
		String accessTokenValue = "access-token";
		if (jwtEncoder != null) {
			accessTokenValue = issueJwtAccessToken(jwtEncoder, "user-1", registeredClient.getClientId(),
					registeredClient.getScopes()).getTokenValue();
		}
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessTokenValue, Instant.now(),
				Instant.now().plusSeconds(300));
		OAuth2RefreshToken refreshToken = new OAuth2RefreshToken2("refresh-token", Instant.now(),
				Instant.now().plus(1, ChronoUnit.HOURS));
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri("https://provider.com/oauth2/authorize").clientId(registeredClient.getClientId())
				.redirectUri(registeredClient.getRedirectUris().iterator().next()).scopes(registeredClient.getScopes())
				.additionalParameters(authorizationRequestAdditionalParameters).state("state").build();
		return OAuth2Authorization.withRegisteredClient(registeredClient).principalName("principal")
				.tokens(OAuth2Tokens.builder().token(authorizationCode).accessToken(accessToken).refreshToken(refreshToken)
						.build())
				.attribute(OAuth2AuthorizationAttributeNames.AUTHORIZATION_REQUEST, authorizationRequest)
				.attribute(OAuth2AuthorizationAttributeNames.AUTHORIZED_SCOPES, authorizationRequest.getScopes());
	}

	private static Jwt issueJwtAccessToken(JwtEncoder jwtEncoder, String subject, String audience, Set<String> scopes) {
		JoseHeader joseHeader = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();

		URL issuer = null;
		try {
			issuer = URI.create("https://oauth2.provider.com").toURL();
		} catch (MalformedURLException e) {
		}

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);

		JwtClaimsSet jwtClaimsSet = JwtClaimsSet.withClaims().issuer(issuer).subject(subject)
				.audience(Collections.singletonList(audience)).issuedAt(issuedAt).expiresAt(expiresAt).notBefore(issuedAt)
				.claim(OAuth2ParameterNames.SCOPE, scopes).build();

		return jwtEncoder.encode(joseHeader, jwtClaimsSet);
	}
}
