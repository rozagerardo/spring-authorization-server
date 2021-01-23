/*
 * Copyright 2020-2021 the original author or authors.
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

import org.springframework.lang.Nullable;

import java.util.Optional;

/**
 * Implementations of this interface are responsible for the management
 * of {@link OAuth2Authorization OAuth 2.0 Authorization(s)}.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2Authorization
 */
public interface OAuth2AuthorizationService {

	/**
	 * Saves the {@link OAuth2Authorization}.
	 *
	 * @param authorization the {@link OAuth2Authorization}
	 */
	void save(OAuth2Authorization authorization);

	/**
	 * Removes the {@link OAuth2Authorization}.
	 *
	 * @param authorization the {@link OAuth2Authorization}
	 */
	void remove(OAuth2Authorization authorization);

	/**
	 * Returns the {@link OAuth2Authorization} containing the provided {@code token},
	 * or {@code null} if not found.
	 *
	 * @param token the token credential
	 * @param tokenType the {@link TokenType token type}
	 * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
	 */
	@Nullable
	OAuth2Authorization findByToken(String token, @Nullable TokenType tokenType);

	/**
	 * Returns the {@link OAuth2Authorization} containing the provided {@code token},
	 * or {@code null} if not found.
	 *
	 * The optional {@code tokenTypeHint} is used only as a hint; if it is unable to locate the token using the given hint,
	 * it will extend its search across all of its supported token types.
	 *
	 * @param token the token credential
	 * @param tokenTypeHint an optional {@link TokenType token type}
	 * @return an optional {@link OAuth2Authorization}
	 */
	Optional<OAuth2Authorization> findByTokenWithHint(String token, Optional<TokenType> tokenTypeHint);

}
