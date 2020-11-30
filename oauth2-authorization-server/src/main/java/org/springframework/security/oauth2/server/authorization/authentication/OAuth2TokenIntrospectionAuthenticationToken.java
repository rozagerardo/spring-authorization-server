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

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.server.authorization.Version;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} implementation used for OAuth 2.0 Token Introspection.
 *
 * @author Gerardo Roza
 * @since 0.0.4
 * @see AbstractAuthenticationToken
 * @see OAuth2TokenIntrospectionAuthenticationProvider
 */
public class OAuth2TokenIntrospectionAuthenticationToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = Version.SERIAL_VERSION_UID;
	private final String tokenValue;
	private final Authentication clientPrincipal;
	private final String tokenTypeHint;
	private final String clientId;
	private final AbstractOAuth2Token token;
	private final boolean tokenActive;

	/**
	 * Constructs an {@code OAuth2TokenIntrospectionAuthenticationToken} using the provided parameters.
	 *
	 * @param tokenValue the token
	 * @param clientPrincipal the authenticated client principal
	 * @param tokenTypeHint the token type hint
	 */
	public OAuth2TokenIntrospectionAuthenticationToken(String tokenValue, Authentication clientPrincipal,
			@Nullable String tokenTypeHint) {
		super(Collections.emptyList());
		Assert.hasText(tokenValue, "token cannot be empty");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.tokenValue = tokenValue;
		this.clientPrincipal = clientPrincipal;
		this.tokenTypeHint = tokenTypeHint;
		this.token = null;
		this.tokenActive = false;
		this.clientId = null;
	}

	/**
	 * Constructs an {@code OAuth2TokenRevocationAuthenticationToken} using the provided parameters.
	 *
	 * @param token the introspected token
	 * @param clientPrincipal the authenticated client principal
	 */
	public OAuth2TokenIntrospectionAuthenticationToken(AbstractOAuth2Token token, boolean tokenActive,
			Authentication clientPrincipal, String clientId) {
		super(Collections.emptyList());
		Assert.notNull(token, "token cannot be null");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		Assert.hasText(clientId, "clientPrincipal cannot be empty");
		this.tokenValue = token.getTokenValue();
		this.token = token;
		this.clientPrincipal = clientPrincipal;
		this.tokenActive = tokenActive;
		this.clientId = clientId;
		this.tokenTypeHint = null;
		setAuthenticated(true); // Indicates that the request was authenticated, even though the introspected token might not be
								// active
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	/**
	 * Returns the token value.
	 *
	 * @return the token value
	 */
	public String getTokenValue() {
		return this.tokenValue;
	}

	/**
	 * Returns the token type hint.
	 *
	 * @return the token type hint
	 */
	@Nullable
	public String getTokenTypeHint() {
		return this.tokenTypeHint;
	}

	/**
	 * Returns the token.
	 * 
	 * @return the token
	 */
	public AbstractOAuth2Token getToken() {
		return token;
	}

	/**
	 * Returns whether the introspected token is active.
	 * 
	 * @return whether the introspected token is active or not
	 */
	public boolean isTokenActive() {
		return tokenActive;
	}

	/**
	 * Returns the clientId.
	 * 
	 * @return the clientId
	 */
	public String getClientId() {
		return clientId;
	}

}
