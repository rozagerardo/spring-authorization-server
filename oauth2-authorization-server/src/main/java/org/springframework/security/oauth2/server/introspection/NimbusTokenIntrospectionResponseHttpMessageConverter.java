package org.springframework.security.oauth2.server.introspection;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;

import net.minidev.json.JSONObject;

public class NimbusTokenIntrospectionResponseHttpMessageConverter
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