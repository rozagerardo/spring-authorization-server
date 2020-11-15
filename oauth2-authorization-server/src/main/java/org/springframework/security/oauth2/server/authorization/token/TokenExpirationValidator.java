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

import java.time.Instant;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;

/**
 * An implementation of {@link OAuth2TokenValidator} to verify a token is not
 * expired.
 * 
 * @author Gerardo Roza
 * @since 0.0.4
 */
public class TokenExpirationValidator implements OAuth2TokenValidator<AbstractOAuth2Token> {

	private final Log logger = LogFactory.getLog(getClass());

	@Override
	public OAuth2TokenValidatorResult validate(AbstractOAuth2Token token) {
		Assert.notNull(token, "token cannot be null");
		Instant expiry = token.getExpiresAt();
		if (expiry != null) {
			if (Instant.now().isAfter(expiry)) {
				OAuth2Error oAuth2Error = createOAuth2Error(String.format("Token expired at %s", expiry));
				return OAuth2TokenValidatorResult.failure(oAuth2Error);
			}
		}
		return OAuth2TokenValidatorResult.success();
	}

	private OAuth2Error createOAuth2Error(String reason) {
		this.logger.debug(reason);
		return new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, reason,
				"https://tools.ietf.org/html/rfc6750#section-3.1");
	}

}
