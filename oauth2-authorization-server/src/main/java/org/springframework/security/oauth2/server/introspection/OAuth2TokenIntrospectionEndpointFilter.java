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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;

/**
 * TODO: add javadocs
 * 
 * @author Gerardo Roza
 */
public class OAuth2TokenIntrospectionEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for token introspection requests.
	 */
	public static final String DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI = "/oauth2/introspect";

	private final OAuth2AuthorizationService authorizationService;
	private final RequestMatcher tokenEndpointMatcher;
	private final HttpMessageConverter<TokenIntrospectionSuccessResponse> tokenIntrospectionHttpResponseConverter = new NimbusTokenIntrospectionResponseHttpMessageConverter();
	private final Collection<JwtDecoder> jwtDecoders;

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the
	 * provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param authorizationService  the authorization service
	 */
	public OAuth2TokenIntrospectionEndpointFilter(RegisteredClientRepository registeredClientRepository,
			Collection<JwtDecoder> jwtDecoders, AuthenticationManager authenticationManager,
			OAuth2AuthorizationService authorizationService) {
		this(registeredClientRepository, jwtDecoders, authenticationManager, authorizationService,
				DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the
	 * provided parameters.
	 *
	 * @param authenticationManager         the authentication manager
	 * @param authorizationService          the authorization service
	 * @param tokenIntrospectionEndpointUri the endpoint {@code URI} for token
	 *                                      introspection requests
	 */
	public OAuth2TokenIntrospectionEndpointFilter(RegisteredClientRepository registeredClientRepository,
			Collection<JwtDecoder> jwtDecoders, AuthenticationManager authenticationManager,
			OAuth2AuthorizationService authorizationService, String tokenIntrospectionEndpointUri) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwtDecoders, "jwtDecoders cannot be empty");
		Assert.hasText(tokenIntrospectionEndpointUri, "tokenIntrospectionEndpointUri cannot be empty");
		this.jwtDecoders = jwtDecoders;
		this.authorizationService = authorizationService;
		this.tokenEndpointMatcher = new AntPathRequestMatcher(tokenIntrospectionEndpointUri, HttpMethod.POST.name());
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.tokenEndpointMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		// obtain Authentication
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (!isPrincipalAuthenticated(principal)) {
			// Pass through the chain with the expectation that the authentication process
			// will commence via AuthenticationEntryPoint
			filterChain.doFilter(request, response);
			return;
		}

		// obtain access token
		String token = request.getParameter("token");
		Optional<TokenType> tokenTypeHint = Optional.ofNullable(request.getParameter("token_type_hint"))
				.map(TokenType::new);
		TokenIntrospectionSuccessResponse tokenIntrospectionResponse;

		try {
			// get client from token
			OAuth2Authorization authorization = findAuthorizationByToken(token, tokenTypeHint)
					.orElseThrow(() -> new InvalidTokenException("Token not found"));

			// check if token corresponds to authorized Client
			OAuth2ClientAuthenticationToken clientAuthentication = principal instanceof OAuth2ClientAuthenticationToken
					? (OAuth2ClientAuthenticationToken) principal
					: null;
			String clientId = authorization.getRegisteredClientId();
			if (clientAuthentication == null || !clientAuthentication.getRegisteredClient().getId().equals(clientId)) {
				throw new InvalidTokenException("Token does not correspond to authenticated client");
			}

			AbstractOAuth2Token oauthToken = authorization.getTokens().getToken(token, tokenTypeHint).get();
			if (authorization.getTokens().getTokenMetadata(oauthToken).isInvalidated()) {
				throw new InvalidTokenException("Token has been invalidated");
			}

			oauthToken = parseJwt(oauthToken);

			validateToken(oauthToken);

			TokenIntrospectionSuccessResponse.Builder builder = new TokenIntrospectionSuccessResponse.Builder(true);
			builder.clientID(new ClientID(clientId));
			TokenToIntrospectionResponseMapper.extractFromToken(oauthToken, builder);
			tokenIntrospectionResponse = builder.build();
		} catch (InvalidTokenException exception) {
			TokenIntrospectionSuccessResponse.Builder builder = new TokenIntrospectionSuccessResponse.Builder(false);
			tokenIntrospectionResponse = builder.build();

		}
		this.sendTokenIntrospectionResponse(response, tokenIntrospectionResponse);
	}

	private Optional<OAuth2Authorization> findAuthorizationByToken(String token, Optional<TokenType> tokenTypeHint) {
		List<TokenType> supportedTokenTypes = new ArrayList<TokenType>(
				Arrays.asList(TokenType.ACCESS_TOKEN, TokenType.REFRESH_TOKEN));
		tokenTypeHint.ifPresent(tType -> {
			if (supportedTokenTypes.remove(tType))
				supportedTokenTypes.add(0, tType);
		});
		for (TokenType tokenType : supportedTokenTypes) {
			OAuth2Authorization authorization = this.authorizationService.findByToken(token, tokenType);
			if (authorization != null)
				return Optional.of(authorization);
		}
		return Optional.empty();
	}

	private void sendTokenIntrospectionResponse(HttpServletResponse response,
			TokenIntrospectionSuccessResponse tokenIntrospectionResponse) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		this.tokenIntrospectionHttpResponseConverter.write(tokenIntrospectionResponse, null, httpResponse);
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
		List<OAuth2TokenValidator<T>> validators;

		if (token instanceof Jwt) {
			validators = new ArrayList<>();
			validators.add((OAuth2TokenValidator<T>) new JwtTimestampValidator());
		} else {
			validators = new ArrayList<>();
			validators.add((OAuth2TokenValidator<T>) new TokenExpirationValidator());
		}
		DelegatingOAuth2TokenValidator<T> tokenValidator = new DelegatingOAuth2TokenValidator<T>(validators);
		OAuth2TokenValidatorResult result = tokenValidator.validate(token);
		if (result.hasErrors()) {
			String errorMessages = result.getErrors().stream().map(OAuth2Error::getErrorCode)
					.collect(Collectors.joining(", ", "Invalid Token:", "."));
			throw new InvalidTokenException(errorMessages);
		}
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
				&& principal.isAuthenticated();
	}
}
