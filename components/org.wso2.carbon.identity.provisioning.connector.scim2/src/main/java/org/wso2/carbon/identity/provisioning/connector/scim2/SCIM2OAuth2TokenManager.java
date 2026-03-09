/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.provisioning.connector.scim2;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONObject;
import org.wso2.scim2.auth.TokenManager;

import org.wso2.scim2.util.SCIM2ClientConfig;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * OAuth 2.0 Client Credentials token manager for SCIM2 outbound provisioning.
 */
public class SCIM2OAuth2TokenManager implements TokenManager {

    private static final Log log = LogFactory.getLog(SCIM2OAuth2TokenManager.class);
    private static final String GRANT_TYPE_CLIENT_CREDENTIALS = "grant_type=client_credentials";
    private static final int MAX_RESPONSE_SIZE = 65536;

    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final String scope;
    private final Object tokenLock = new Object();

    private volatile String accessToken;

    public SCIM2OAuth2TokenManager(String tokenEndpoint, String clientId, String clientSecret, String scope) {

        if (StringUtils.isBlank(tokenEndpoint)) {
            throw new IllegalArgumentException("Token endpoint URL must not be empty");
        }
        if (!tokenEndpoint.toLowerCase().startsWith("https://")) {
            throw new IllegalArgumentException(
                    "Token endpoint must use HTTPS. Provided: " + tokenEndpoint);
        }
        if (StringUtils.isBlank(clientId)) {
            throw new IllegalArgumentException("Client ID must not be empty");
        }
        if (StringUtils.isBlank(clientSecret)) {
            throw new IllegalArgumentException("Client secret must not be empty");
        }

        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scope = scope;
    }

    @Override
    public String getAccessToken() throws Exception {

        String token = accessToken;
        if (token != null) {
            return token;
        }
        synchronized (tokenLock) {
            if (accessToken != null) {
                return accessToken;
            }
            accessToken = acquireToken();
            return accessToken;
        }
    }

    @Override
    public String refreshToken(String expiredToken) throws Exception {

        synchronized (tokenLock) {
            accessToken = null;
            accessToken = acquireToken();
            if (log.isDebugEnabled()) {
                log.debug("Successfully refreshed OAuth2 access token from: " + tokenEndpoint);
            }
            return accessToken;
        }
    }

    private String acquireToken() throws IOException {

        HttpURLConnection connection = null;
        try {
            URL url = new URL(tokenEndpoint);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            SCIM2ClientConfig clientConfig = SCIM2ClientConfig.getInstance();
            connection.setConnectTimeout(clientConfig.getHttpConnectionTimeoutInMillis());
            connection.setReadTimeout(clientConfig.getHttpReadTimeoutInMillis());
            connection.setInstanceFollowRedirects(false);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            // Basic Auth header: Base64(clientId:clientSecret).
            String credentials = clientId + ":" + clientSecret;
            String encodedCredentials = Base64.getEncoder().encodeToString(
                    credentials.getBytes(StandardCharsets.UTF_8));
            connection.setRequestProperty("Authorization", "Basic " + encodedCredentials);

            // Build request body.
            String requestBody = GRANT_TYPE_CLIENT_CREDENTIALS;
            if (StringUtils.isNotBlank(scope)) {
                requestBody += "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8.name());
            }

            try (OutputStream os = connection.getOutputStream()) {
                os.write(requestBody.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = connection.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                String errorResponse = readResponse(connection, true);
                // Sanitize error response to prevent log injection via control characters.
                String sanitizedError = errorResponse.replaceAll("[\\r\\n\\t]", " ");
                throw new IOException("Token endpoint returned HTTP " + responseCode +
                        ". Response: " + sanitizedError);
            }

            String responseBody = readResponse(connection, false);
            JSONObject jsonResponse = new JSONObject(responseBody);

            if (!jsonResponse.has("access_token")) {
                throw new IOException("Token endpoint response does not contain 'access_token' field");
            }

            String token = jsonResponse.getString("access_token");
            if (log.isDebugEnabled()) {
                log.debug("Successfully acquired OAuth2 access token from: " + tokenEndpoint);
            }
            return token;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private String readResponse(HttpURLConnection connection, boolean errorStream) throws IOException {

        StringBuilder response = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                errorStream ? connection.getErrorStream() : connection.getInputStream(),
                StandardCharsets.UTF_8))) {
            String line;
            int totalRead = 0;
            while ((line = reader.readLine()) != null) {
                totalRead += line.length();
                if (totalRead > MAX_RESPONSE_SIZE) {
                    throw new IOException("Token endpoint response exceeded maximum size of " + MAX_RESPONSE_SIZE +
                            " characters");
                }
                response.append(line);
            }
        }
        return response.toString();
    }
}
