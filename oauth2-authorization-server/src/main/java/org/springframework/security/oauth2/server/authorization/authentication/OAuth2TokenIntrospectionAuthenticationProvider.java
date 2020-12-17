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

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes2;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.TokenExpirationValidator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.stream.Collectors;

/**
 * An {@link AuthenticationProvider} implementation for OAuth 2.0 Token Introspection.
 *
 * @author Gerardo Roza
 * @since 0.0.4
 * @see OAuth2TokenIntrospectionAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.1">Section 2.1 - Introspection Request</a>
 */
public class OAuth2TokenIntrospectionAuthenticationProvider implements AuthenticationProvider {
	private final OAuth2AuthorizationService authorizationService;
	private final Collection<JwtDecoder> jwtDecoders;

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param jwtDecoders all available decoders that might be used to parse the token as a JWT-encoded token
	 */
	public OAuth2TokenIntrospectionAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			Collection<JwtDecoder> jwtDecoders) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
		this.jwtDecoders = jwtDecoders;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2TokenIntrospectionAuthenticationToken tokenIntrospectionAuthentication = (OAuth2TokenIntrospectionAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(
				tokenIntrospectionAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		TokenType tokenType = null;
		String tokenTypeHint = tokenIntrospectionAuthentication.getTokenTypeHint();
		if (StringUtils.hasText(tokenTypeHint)) {
			if (TokenType.REFRESH_TOKEN.getValue().equals(tokenTypeHint)) {
				tokenType = TokenType.REFRESH_TOKEN;
			} else if (TokenType.ACCESS_TOKEN.getValue().equals(tokenTypeHint)) {
				tokenType = TokenType.ACCESS_TOKEN;
			}
		}

		try {
			OAuth2Authorization authorization = this.authorizationService
					.findByToken(tokenIntrospectionAuthentication.getTokenValue(), tokenType);
			if (authorization == null) {
				throw new IntrospectionTokenException("Token not found");
			}

			if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
				throw new IntrospectionTokenException("Invalid client");
			}

			AbstractOAuth2Token token = authorization.getTokens().getToken(tokenIntrospectionAuthentication.getTokenValue());

			if (authorization.getTokens().getTokenMetadata(token).isInvalidated()) {
				throw new IntrospectionTokenException("Token has been invalidated");
			}

			token = parseJwt(token);

			validateToken(token);

			return new OAuth2TokenIntrospectionAuthenticationToken(clientPrincipal, registeredClient.getClientId(), token);
		} catch (IntrospectionTokenException exception) {
			return new OAuth2TokenIntrospectionAuthenticationToken(clientPrincipal, registeredClient.getClientId(), null);
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2TokenIntrospectionAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private AbstractOAuth2Token parseJwt(AbstractOAuth2Token token) {
		for (JwtDecoder jwtDecoder : this.jwtDecoders) {
			try {
				return jwtDecoder.decode(token.getTokenValue());
			} catch (JwtException ex) {
				// token might not be a JWT, or can't be processed with this decoder.
			}
		}
		return token;
	}

	@SuppressWarnings("unchecked")
	private <T extends AbstractOAuth2Token> void validateToken(T token) {
		OAuth2TokenValidator<T> tokenValidator = (token instanceof Jwt) ? (OAuth2TokenValidator<T>) new JwtTimestampValidator()
				: (OAuth2TokenValidator<T>) new TokenExpirationValidator();
		OAuth2TokenValidatorResult result = tokenValidator.validate(token);
		if (result.hasErrors()) {
			String errorMessages = result.getErrors().stream().map(OAuth2Error::getErrorCode)
					.collect(Collectors.joining(", ", "Invalid Token:", "."));
			throw new IntrospectionTokenException(errorMessages);
		}
	}

	/**
	 * Exception that can be triggered when a token is found invalid.
	 *
	 * @author Gerardo Roza
	 */
	private static class IntrospectionTokenException extends RuntimeException {

		private static final long serialVersionUID = Version.SERIAL_VERSION_UID;

		/**
		 * Construct an instance of {@link IntrospectionTokenException} given the provided description.
		 *
		 * @param description the description
		 */
		IntrospectionTokenException(String description) {
			this(description, null);
		}

		/**
		 * Construct an instance of {@link IntrospectionTokenException} given the provided description and cause
		 *
		 * @param description the description
		 * @param cause the causing exception
		 */
		IntrospectionTokenException(String description, Throwable cause) {
			super(description, cause);
		}
	}

}
