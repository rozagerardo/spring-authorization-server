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

package org.springframework.security.oauth2.server.introspection;

import static java.util.stream.Collectors.toList;

import java.net.URISyntaxException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.BiConsumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;

/**
 * Mapper that helps populate {@code TokenIntrospectionSuccessResponse} fields
 * from different{@code AbstractOAuth2Token} implementations.
 * 
 * @see OAuth2AccessToken
 * @see Jwt
 * 
 * @author Gerardo Roza
 *
 */
public final class TokenToIntrospectionResponseMapper {

	private static final Log logger = LogFactory.getLog(TokenToIntrospectionResponseMapper.class);

	private static final Map<Class<? extends AbstractOAuth2Token>, BiConsumer<AbstractOAuth2Token, TokenIntrospectionSuccessResponse.Builder>> supportedTokens;
	static {
		Map<Class<? extends AbstractOAuth2Token>, BiConsumer<AbstractOAuth2Token, TokenIntrospectionSuccessResponse.Builder>> tokenMap = new HashMap<>();
		tokenMap.put(OAuth2AccessToken.class,
				(token, builder) -> extractFromOAuth2AccessToken((OAuth2AccessToken) token, builder));
		tokenMap.put(Jwt.class, (token, builder) -> extractFromJwt((Jwt) token, builder));
		supportedTokens = Collections.unmodifiableMap(tokenMap);
	}

	private TokenToIntrospectionResponseMapper() {
	}

	/**
	 * Extracts all the corresponding fields from an {@code OAuth2AccessToken}.
	 *
	 * @param scope The token scope, {@code null} if not specified.
	 *
	 * @return This builder.
	 */
	private static TokenIntrospectionSuccessResponse.Builder extractFromOAuth2AccessToken(
			final OAuth2AccessToken accessToken, TokenIntrospectionSuccessResponse.Builder builder) {
		builder.scope(Scope.parse(String.join(" ", accessToken.getScopes())));
		builder.tokenType(AccessTokenType.BEARER);
		return builder;
	}

	/**
	 * Extracts all the corresponding fields from an {@code OAuth2AccessToken}.
	 *
	 * @param scope The token scope, {@code null} if not specified.
	 *
	 * @return This builder.
	 */
	private static TokenIntrospectionSuccessResponse.Builder extractFromJwt(final Jwt jwt,
			TokenIntrospectionSuccessResponse.Builder builder) {
		builder.scope(Scope.parse(String.join(" ", jwt.getClaimAsStringList(OAuth2ParameterNames.SCOPE))));
		builder.tokenType(AccessTokenType.BEARER);
		builder.notBeforeTime(Date.from(jwt.getNotBefore()));
		builder.subject(new Subject(jwt.getSubject()));
		builder.audience(jwt.getAudience().stream().map(Audience::new).collect(toList()));
		try {
			builder.issuer(new Issuer(jwt.getIssuer().toURI()));
		} catch (URISyntaxException e) {
			logger.debug("Error extracting issuer claim from JWT into Token Introspection response", e);
		}
		return builder;
	}

	/**
	 * Extracts all the corresponding fields from an {@code OAuth2AccessToken}.
	 *
	 * @param scope The token scope, {@code null} if not specified.
	 *
	 * @return This builder.
	 */
	public static TokenIntrospectionSuccessResponse.Builder extractFromToken(final AbstractOAuth2Token token,
			TokenIntrospectionSuccessResponse.Builder builder) {
		supportedTokens.get(token.getClass()).accept(token, builder);
		return builder;
	}

}
