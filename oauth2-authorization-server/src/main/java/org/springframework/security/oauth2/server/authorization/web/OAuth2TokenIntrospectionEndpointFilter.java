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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;

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

	private final AuthenticationManager authenticationManager;
	private final OAuth2AuthorizationService authorizationService;
	private final RegisteredClientRepository registeredClientRepository;
	private final RequestMatcher tokenEndpointMatcher;
//	private final HttpMessageConverter<TokenIntrospectionResponse> accessTokenHttpResponseConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the
	 * provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param authorizationService  the authorization service
	 */
	public OAuth2TokenIntrospectionEndpointFilter(RegisteredClientRepository registeredClientRepository,
			AuthenticationManager authenticationManager, OAuth2AuthorizationService authorizationService) {
		this(registeredClientRepository, authenticationManager, authorizationService,
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
			AuthenticationManager authenticationManager, OAuth2AuthorizationService authorizationService,
			String tokenIntrospectionEndpointUri) {
		Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.hasText(tokenIntrospectionEndpointUri, "tokenIntrospectionEndpointUri cannot be empty");
		this.registeredClientRepository = registeredClientRepository;
		this.authenticationManager = authenticationManager;
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
		String tokenTypeHint = request.getParameter("token_type_hint");

		// get client from token
		Optional<OAuth2Authorization> authorization = findAuthorizationByToken(token, tokenTypeHint);

		// check if token corresponds to authorized Client
		RegisteredClient registeredClient = this.registeredClientRepository
				.findByClientId(request.getParameter("client_id"));

		// check token validity

		// if valid
		if (true) {
			// if jwt, decode and get further info
//			sendAccessTokenResponse(response, accessToken);
		}
		// else if invalid

	}

	private Optional<OAuth2Authorization> findAuthorizationByToken(String token, String tokenTypeHint) {
		List<TokenType> supportedTokenTypes = new ArrayList<TokenType>(
				Arrays.asList(TokenType.ACCESS_TOKEN, TokenType.REFRESH_TOKEN));
		Optional.ofNullable(tokenTypeHint).map(TokenType::new).ifPresent(tType -> {
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

	private void sendAccessTokenResponse(HttpServletResponse response, String accessToken) throws IOException {

		TokenIntrospectionSuccessResponse.Builder builder = new TokenIntrospectionSuccessResponse.Builder(true);
		TokenIntrospectionResponse tokenIntrospectionResponse = builder.build();
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
//		this.accessTokenHttpResponseConverter.write(tokenIntrospectionResponse, null, httpResponse);
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName,
				"https://tools.ietf.org/html/rfc6749#section-5.2");
		throw new OAuth2AuthenticationException(error);
	}

	private static class AuthorizationCodeAuthenticationConverter
			implements Converter<HttpServletRequest, Authentication> {

		@Override
		public Authentication convert(HttpServletRequest request) {
			// grant_type (REQUIRED)
			String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
			if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
				return null;
			}

			Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

			MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

			// code (REQUIRED)
			String code = parameters.getFirst(OAuth2ParameterNames.CODE);
			if (!StringUtils.hasText(code) || parameters.get(OAuth2ParameterNames.CODE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CODE);
			}

			// redirect_uri (REQUIRED)
			// Required only if the "redirect_uri" parameter was included in the
			// authorization request
			String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
			if (StringUtils.hasText(redirectUri) && parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
			}

			Map<String, Object> additionalParameters = parameters.entrySet().stream()
					.filter(e -> !e.getKey().equals(OAuth2ParameterNames.GRANT_TYPE)
							&& !e.getKey().equals(OAuth2ParameterNames.CLIENT_ID)
							&& !e.getKey().equals(OAuth2ParameterNames.CODE)
							&& !e.getKey().equals(OAuth2ParameterNames.REDIRECT_URI))
					.collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get(0)));

			return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri,
					additionalParameters);
		}
	}

	private static class ClientCredentialsAuthenticationConverter
			implements Converter<HttpServletRequest, Authentication> {

		@Override
		public Authentication convert(HttpServletRequest request) {
			// grant_type (REQUIRED)
			String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
			if (!AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(grantType)) {
				return null;
			}

			Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

			MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

			// scope (OPTIONAL)
			String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
			if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
			}
			if (StringUtils.hasText(scope)) {
				Set<String> requestedScopes = new HashSet<>(
						Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
				return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal, requestedScopes);
			}

			return new OAuth2ClientCredentialsAuthenticationToken(clientPrincipal);
		}
	}

	private static boolean isPrincipalAuthenticated(Authentication principal) {
		return principal != null && !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass())
				&& principal.isAuthenticated();
	}
}
