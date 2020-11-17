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

import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames2;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.TokenExpirationValidator;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;

import net.minidev.json.JSONObject;

/**
 * A {@code Filter} for the OAuth 2.0 Token Introspection endpoint.
 *
 * @author Gerardo Roza
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2">Section 2 - Introspection Endpoint</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.1">Section 2.1 - Introspection Request</a>
 * @since 0.0.4
 */
public class OAuth2TokenIntrospectionEndpointFilter extends OncePerRequestFilter {

	/**
	 * The default endpoint {@code URI} for token introspection requests.
	 */
	public static final String DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI = "/oauth2/introspect";

	private final RequestMatcher tokenEndpointMatcher;
	private final OAuth2AuthorizationService authorizationService;
	private final HttpMessageConverter<TokenIntrospectionSuccessResponse> tokenIntrospectionHttpResponseConverter = new NimbusTokenIntrospectionResponseHttpMessageConverter();
	private final Collection<JwtDecoder> jwtDecoders;
	private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter = new OAuth2ErrorHttpMessageConverter();

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager the authentication manager
	 * @param authorizationService  the authorization service
	 */
	public OAuth2TokenIntrospectionEndpointFilter(OAuth2AuthorizationService authorizationService,
			Collection<JwtDecoder> jwtDecoders) {
		this(authorizationService, jwtDecoders, DEFAULT_TOKEN_INTROSPECTION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionEndpointFilter} using the provided parameters.
	 *
	 * @param authenticationManager         the authentication manager
	 * @param authorizationService          the authorization service
	 * @param tokenIntrospectionEndpointUri the endpoint {@code URI} for token introspection requests
	 */
	public OAuth2TokenIntrospectionEndpointFilter(OAuth2AuthorizationService authorizationService,
			Collection<JwtDecoder> jwtDecoders, String tokenIntrospectionEndpointUri) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.hasText(tokenIntrospectionEndpointUri, "tokenIntrospectionEndpointUri cannot be empty");
		this.jwtDecoders = jwtDecoders != null ? jwtDecoders : Collections.emptyList();
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

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);
		try {
			// token (REQUIRED)
			String token = parameters.getFirst(OAuth2ParameterNames2.TOKEN);
			if (!StringUtils.hasText(token) || parameters.get(OAuth2ParameterNames2.TOKEN).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames2.TOKEN);
			}

			// token_type_hint (OPTIONAL)
			Optional<TokenType> tokenTypeHint = Optional.ofNullable(parameters.getFirst(OAuth2ParameterNames2.TOKEN_TYPE_HINT))
					.map(TokenType::new);
			if (tokenTypeHint.isPresent() && parameters.get(OAuth2ParameterNames2.TOKEN_TYPE_HINT).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames2.TOKEN_TYPE_HINT);
			}

			TokenIntrospectionSuccessResponse tokenIntrospectionResponse;

			try {
				// get client from token
				OAuth2Authorization authorization = findAuthorizationByToken(token, tokenTypeHint)
						.orElseThrow(() -> new InvalidTokenException("Token not found"));

				// check if token corresponds to authorized Client
				OAuth2ClientAuthenticationToken clientAuthentication = principal instanceof OAuth2ClientAuthenticationToken
						? (OAuth2ClientAuthenticationToken) principal
						: null;
				if (clientAuthentication == null
						|| !clientAuthentication.getRegisteredClient().getId().equals(authorization.getRegisteredClientId())) {
					throw new InvalidTokenException("Token does not correspond to authenticated client");
				}

				// we've obtained the authorization from the token, we shouldn't expect an empty response here
				AbstractOAuth2Token oauthToken = authorization.getTokens().getToken(token).get();
				if (authorization.getTokens().getTokenMetadata(oauthToken).isInvalidated()) {
					throw new InvalidTokenException("Token has been invalidated");
				}

				oauthToken = parseJwt(oauthToken);

				validateToken(oauthToken);

				TokenIntrospectionSuccessResponse.Builder builder = new TokenIntrospectionSuccessResponse.Builder(true);
				builder.clientID(new ClientID(clientAuthentication.getRegisteredClient().getClientId()));
				Optional.ofNullable(oauthToken.getIssuedAt()).map(Date::from).ifPresent(builder::issueTime);
				Optional.ofNullable(oauthToken.getExpiresAt()).map(Date::from).ifPresent(builder::expirationTime);
				TokenToIntrospectionResponseFieldsMapper.extractFromToken(oauthToken, builder);
				tokenIntrospectionResponse = builder.build();
			} catch (InvalidTokenException exception) {
				TokenIntrospectionSuccessResponse.Builder builder = new TokenIntrospectionSuccessResponse.Builder(false);
				tokenIntrospectionResponse = builder.build();
			}
			this.sendTokenIntrospectionResponse(response, tokenIntrospectionResponse);
		} catch (OAuth2AuthenticationException ex) {
			SecurityContextHolder.clearContext();
			sendErrorResponse(response, ex.getError());
		}
	}

	private void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
		this.errorHttpResponseConverter.write(error, null, httpResponse);
	}

	private Optional<OAuth2Authorization> findAuthorizationByToken(String token, Optional<TokenType> tokenTypeHint) {
		List<TokenType> supportedTokenTypes = new ArrayList<TokenType>(
				Arrays.asList(TokenType.ACCESS_TOKEN, TokenType.REFRESH_TOKEN, TokenType.ID_TOKEN));
		tokenTypeHint.ifPresent(tType -> {
			if (supportedTokenTypes.remove(tType))
				supportedTokenTypes.add(0, tType);
		});
		for (TokenType tokenType : supportedTokenTypes) {
			OAuth2Authorization authorization = this.authorizationService.findByToken(token, tokenType);
			if (authorization != null) {
				return Optional.of(authorization);
			}
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
		OAuth2TokenValidator<T> tokenValidator = (token instanceof Jwt) ? (OAuth2TokenValidator<T>) new JwtTimestampValidator()
				: (OAuth2TokenValidator<T>) new TokenExpirationValidator();
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

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Token Introspection Parameter: " + parameterName,
				"https://tools.ietf.org/html/rfc7662#section-2.1");
		throw new OAuth2AuthenticationException(error);
	}

	/**
	 * Mapper that helps populate {@code TokenIntrospectionSuccessResponse} fields from different{@code AbstractOAuth2Token}
	 * implementations.
	 * 
	 * @see OAuth2AccessToken
	 * @see Jwt
	 * 
	 * @author Gerardo Roza
	 *
	 */
	private static final class TokenToIntrospectionResponseFieldsMapper {

		private static final Log logger = LogFactory.getLog(TokenToIntrospectionResponseFieldsMapper.class);

		private static final Map<Class<? extends AbstractOAuth2Token>, BiConsumer<AbstractOAuth2Token, TokenIntrospectionSuccessResponse.Builder>> supportedTokens;
		static {
			Map<Class<? extends AbstractOAuth2Token>, BiConsumer<AbstractOAuth2Token, TokenIntrospectionSuccessResponse.Builder>> tokenMap = new HashMap<>();
			tokenMap.put(OAuth2AccessToken.class,
					(token, builder) -> extractFromOAuth2AccessToken((OAuth2AccessToken) token, builder));
			tokenMap.put(Jwt.class, (token, builder) -> extractFromJwt((Jwt) token, builder));
			supportedTokens = Collections.unmodifiableMap(tokenMap);
		}

		private TokenToIntrospectionResponseFieldsMapper() {
		}

		/**
		 * Extracts all the corresponding fields from an {@code OAuth2AccessToken}.
		 *
		 * @param scope The token scope, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		private static TokenIntrospectionSuccessResponse.Builder extractFromOAuth2AccessToken(final OAuth2AccessToken accessToken,
				TokenIntrospectionSuccessResponse.Builder builder) {
			Collection<String> scopes = accessToken.getScopes();
			if (!scopes.isEmpty()) {
				builder.scope(Scope.parse(String.join(" ", scopes)));
			}
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
			builder.tokenType(AccessTokenType.BEARER);
			Optional.ofNullable(jwt.getSubject()).map(Subject::new).ifPresent(builder::subject);
			Optional.ofNullable(jwt.getId()).map(JWTID::new).ifPresent(builder::jwtID);
			Optional.ofNullable(jwt.getAudience()).map(audienceList -> audienceList.stream().map(Audience::new).collect(toList()))
					.ifPresent(builder::audience);
			Optional.ofNullable(jwt.getNotBefore()).map(Date::from).ifPresent(builder::notBeforeTime);
			Optional.ofNullable(jwt.getClaimAsStringList(OAuth2ParameterNames2.SCOPE))
					.map(scopes -> Scope.parse(String.join(" ", scopes))).ifPresent(builder::scope);

			Optional.ofNullable(jwt.getIssuer()).map(issuer -> {
				try {
					return issuer.toURI();
				} catch (URISyntaxException e) {
					logger.debug("Error extracting issuer claim from JWT into Token Introspection response", e);
					return null;
				}
			}).map(Issuer::new).ifPresent(builder::issuer);
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
			Optional.ofNullable(supportedTokens.get(token.getClass())).ifPresent(consumer -> consumer.accept(token, builder));
			return builder;
		}
	}

	/**
	 * Exception that can be triggered when a token is found invalid.
	 * 
	 * @author Gerardo Roza
	 *
	 */
	private static class InvalidTokenException extends RuntimeException {

		/**
		 * Construct an instance of {@link InvalidTokenException} given the provided description.
		 *
		 * @param description the description
		 */
		public InvalidTokenException(String description) {
			this(description, null);
		}

		/**
		 * Construct an instance of {@link InvalidTokenException} given the provided description and cause
		 * 
		 * @param description the description
		 * @param cause       the causing exception
		 */
		public InvalidTokenException(String description, Throwable cause) {
			super(description, cause);
		}
	}

	protected static class NimbusTokenIntrospectionResponseHttpMessageConverter
			extends AbstractHttpMessageConverter<TokenIntrospectionSuccessResponse> {

		private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

		private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<Map<String, Object>>() {
		};

		private GenericHttpMessageConverter<Object> jsonMessageConverter = new MappingJackson2HttpMessageConverter();

		public NimbusTokenIntrospectionResponseHttpMessageConverter() {
			super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
		}

		@Override
		protected boolean supports(Class<?> clazz) {
			return OAuth2AccessTokenResponse.class.isAssignableFrom(clazz);
		}

		@Override
		@SuppressWarnings("unchecked")
		protected TokenIntrospectionSuccessResponse readInternal(Class<? extends TokenIntrospectionSuccessResponse> clazz,
				HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
			try {
				Map<String, Object> tokenIntrospectionResponseParameters = (Map<String, Object>) this.jsonMessageConverter
						.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
				JSONObject jsonObject = new JSONObject(tokenIntrospectionResponseParameters);
				return TokenIntrospectionSuccessResponse.parse(jsonObject);
			} catch (Exception ex) {
				throw new HttpMessageNotReadableException(
						"An error occurred reading the Token Introspection Response: " + ex.getMessage(), ex, inputMessage);
			}
		}

		@Override
		protected void writeInternal(TokenIntrospectionSuccessResponse tokenIntrospectionResponse,
				HttpOutputMessage outputMessage) throws HttpMessageNotWritableException {
			try {

				Map<String, Object> tokenIntrospectionResponseParameters = tokenIntrospectionResponse.toJSONObject();
				this.jsonMessageConverter.write(tokenIntrospectionResponseParameters, STRING_OBJECT_MAP.getType(),
						MediaType.APPLICATION_JSON, outputMessage);
			} catch (Exception ex) {
				throw new HttpMessageNotWritableException(
						"An error occurred writing the Token Introspection Response: " + ex.getMessage(), ex);
			}
		}
	}
}
