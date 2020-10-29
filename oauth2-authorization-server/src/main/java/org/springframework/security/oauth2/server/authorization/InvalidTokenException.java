/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.oauth2.core.OAuth2Error;

public class InvalidTokenException extends RuntimeException {

	private final OAuth2Error error;

	/**
	 * Construct an instance of {@link InvalidTokenException} given the provided
	 * description.
	 *
	 * The description will be wrapped into an
	 * {@link org.springframework.security.oauth2.core.OAuth2Error} instance as the
	 * {@code error_description}.
	 * 
	 * @param description the description
	 */
	public InvalidTokenException(String description) {
		this(description, null);
	}

	/**
	 * Construct an instance of {@link InvalidTokenException} given the provided
	 * description and cause
	 *
	 * The description will be wrapped into an
	 * {@link org.springframework.security.oauth2.core.OAuth2Error} instance as the
	 * {@code error_description}.
	 * 
	 * @param description the description
	 * @param cause       the causing exception
	 */
	public InvalidTokenException(String description, Throwable cause) {
		super(description, cause);
		this.error = BearerTokenErrors.invalidToken(description);
	}

	/**
	 * Returns the {@link OAuth2Error OAuth 2.0 Error}.
	 * 
	 * @return the {@link OAuth2Error}
	 */
	public OAuth2Error getError() {
		return this.error;
	}

}
