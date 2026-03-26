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

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.fail;

/**
 * Tests for SCIM2OAuth2TokenManager.
 */
public class SCIM2OAuth2TokenManagerTest {

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Token endpoint URL must not be empty")
    public void testConstructorWithEmptyTokenEndpoint() {

        new SCIM2OAuth2TokenManager("", "clientId", "clientSecret", null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Token endpoint URL must not be empty")
    public void testConstructorWithNullTokenEndpoint() {

        new SCIM2OAuth2TokenManager(null, "clientId", "clientSecret", null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Token endpoint must use HTTPS.*")
    public void testConstructorWithHttpEndpoint() {

        new SCIM2OAuth2TokenManager("http://token.example.com/token", "clientId", "clientSecret", null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Client ID must not be empty")
    public void testConstructorWithEmptyClientId() {

        new SCIM2OAuth2TokenManager("https://token.example.com/token", "", "clientSecret", null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class,
            expectedExceptionsMessageRegExp = "Client secret must not be empty")
    public void testConstructorWithEmptyClientSecret() {

        new SCIM2OAuth2TokenManager("https://token.example.com/token", "clientId", "", null);
    }

    @Test
    public void testConstructorWithValidParameters() {

        SCIM2OAuth2TokenManager tokenManager = new SCIM2OAuth2TokenManager(
                "https://token.example.com/token", "clientId", "clientSecret", "openid");
        assertNotNull(tokenManager);
    }

    @Test
    public void testConstructorWithNullScope() {

        SCIM2OAuth2TokenManager tokenManager = new SCIM2OAuth2TokenManager(
                "https://token.example.com/token", "clientId", "clientSecret", null);
        assertNotNull(tokenManager);
    }

    @Test
    public void testHttpsValidationIsCaseInsensitive() {

        SCIM2OAuth2TokenManager tokenManager = new SCIM2OAuth2TokenManager(
                "HTTPS://token.example.com/token", "clientId", "clientSecret", null);
        assertNotNull(tokenManager);
    }

    @Test
    public void testGetAccessTokenFailsWithUnreachableEndpoint() {

        SCIM2OAuth2TokenManager tokenManager = new SCIM2OAuth2TokenManager(
                "https://localhost:19999/nonexistent/token", "clientId", "clientSecret", null);
        try {
            tokenManager.getAccessToken();
            fail("Expected exception when token endpoint is unreachable");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testRefreshTokenFailsWithUnreachableEndpoint() {

        SCIM2OAuth2TokenManager tokenManager = new SCIM2OAuth2TokenManager(
                "https://localhost:19999/nonexistent/token", "clientId", "clientSecret", null);
        try {
            tokenManager.refreshToken(null);
            fail("Expected exception when token endpoint is unreachable");
        } catch (Exception e) {
            assertNotNull(e);
        }
    }
}
