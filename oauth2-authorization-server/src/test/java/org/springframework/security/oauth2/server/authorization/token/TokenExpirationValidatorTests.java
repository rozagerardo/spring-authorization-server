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

package org.springframework.security.oauth2.server.authorization.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;

import org.junit.Test;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

/**
 * Tests for {@link TokenExpirationValidator}.
 * 
 * @author Gerardo Roza
 *
 */
public class TokenExpirationValidatorTests {

	private TokenExpirationValidator validator = new TokenExpirationValidator();

	@Test
	public void constructorWhenTokenNullThenThrowIllegalArgumentException() {
		assertThatThrownBy(() -> validator.validate(null)).isInstanceOf(IllegalArgumentException.class)
				.hasMessage("token cannot be null");
	}

	@Test
	public void validateWhenExpiredTokenThenResultWithError() throws Exception {
		AbstractOAuth2Token token = mock(AbstractOAuth2Token.class);
		Instant expiresAt = Instant.now().minusSeconds(3600);
		when(token.getExpiresAt()).thenReturn(expiresAt);

		OAuth2TokenValidatorResult result = this.validator.validate(token);

		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors()).isNotEmpty().singleElement()
				.extracting(OAuth2Error::getErrorCode, OAuth2Error::getDescription, OAuth2Error::getUri)
				.containsExactly(OAuth2ErrorCodes.INVALID_TOKEN, String.format("Token expired at %s", expiresAt),
						"https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	@Test
	public void validateWhenNotExpiredTokenThenResultWithNoError() throws Exception {
		AbstractOAuth2Token token = mock(AbstractOAuth2Token.class);
		Instant expiresAt = Instant.now().plusSeconds(3600);
		when(token.getExpiresAt()).thenReturn(expiresAt);

		OAuth2TokenValidatorResult result = this.validator.validate(token);

		assertThat(result.hasErrors()).isFalse();
		assertThat(result.getErrors()).isEmpty();
	}

}
