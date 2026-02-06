/*
 * Copyright (c) 2018-2026, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.provisioning.connector.scim2.test;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorConstants;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorFactory;
import org.wso2.scim2.util.AuthenticationType;

import java.lang.reflect.Method;
import java.util.List;

public class SCIM2ProvisioningConnectorFactoryTest {

    private SCIM2ProvisioningConnectorFactory scim2ProvisioningConnectorFactory;

    @BeforeMethod
    public void setUp() {

        scim2ProvisioningConnectorFactory = new SCIM2ProvisioningConnectorFactory();
    }

    @Test
    public void testGetConnectorType() {

        Assert.assertEquals(scim2ProvisioningConnectorFactory.getConnectorType(),
                scim2ProvisioningConnectorFactory.SCIM2);
    }

    @Test
    public void testGetConfigurationProperties() {

        // Get configuration properties.
        List<Property> properties = scim2ProvisioningConnectorFactory.getConfigurationProperties();

        // Verify properties are returned.
        Assert.assertNotNull(properties);
        Assert.assertEquals(properties.size(), 10, "Should have 10 configuration properties");
    }

    @Test
    public void testBuildConnectorWithBasicAuth() throws Exception {

        // Create properties for BASIC authentication.
        // Properties are already decrypted at IDP DAO layer.
        Property[] properties = createBasicAuthPropertiesWithPlainValues("testUser", "testPassword");

        AbstractOutboundProvisioningConnector connector = invokeBuildConnector(properties);

        // Verify connector was created.
        Assert.assertNotNull(connector);
    }

    @Test
    public void testBuildConnectorWithBearerAuth() throws Exception {

        // Create properties for BEARER authentication.
        // Properties are already decrypted at IDP DAO layer.
        Property[] properties = createBearerAuthPropertiesWithPlainValues("test-bearer-token");

        AbstractOutboundProvisioningConnector connector = invokeBuildConnector(properties);

        // Verify connector was created.
        Assert.assertNotNull(connector);
    }

    @Test
    public void testBuildConnectorWithApiKeyAuth() throws Exception {

        // Create properties for API_KEY authentication.
        // Properties are already decrypted at IDP DAO layer.
        Property[] properties = createApiKeyAuthPropertiesWithPlainValues("X-API-Key", "test-api-key");

        AbstractOutboundProvisioningConnector connector = invokeBuildConnector(properties);

        // Verify connector was created.
        Assert.assertNotNull(connector);
    }

    @Test
    public void testGetConfigurationPropertiesContainsAllAuthTypes() {

        // Get configuration properties.
        List<Property> properties = scim2ProvisioningConnectorFactory.getConfigurationProperties();

        // Verify properties are returned.
        Assert.assertNotNull(properties);
        Assert.assertTrue(properties.size() > 0, "Configuration properties should not be empty.");

        // Verify authentication mode property exists.
        Property authModeProperty = findPropertyByName(properties, SCIM2ProvisioningConnectorConstants.SCIM2_AUTHENTICATION_MODE);
        Assert.assertNotNull(authModeProperty, "Authentication mode property should exist.");
        Assert.assertEquals(authModeProperty.getType(), "enum", "Authentication mode should be enum type.");
        Assert.assertNotNull(authModeProperty.getOptions(), "Authentication mode should have options.");

        // Verify all 4 auth types are present.
        String[] options = authModeProperty.getOptions();
        Assert.assertTrue(containsOption(options, AuthenticationType.BASIC.getValue()),
                "Should contain BASIC auth type.");
        Assert.assertTrue(containsOption(options, AuthenticationType.BEARER.getValue()),
                "Should contain BEARER auth type.");
        Assert.assertTrue(containsOption(options, AuthenticationType.API_KEY.getValue()),
                "Should contain API_KEY auth type.");
        Assert.assertTrue(containsOption(options, AuthenticationType.NONE.getValue()),
                "Should contain NONE auth type.");
    }

    /**
     * Helper method to create BASIC authentication properties with plain values.
     * Properties are already decrypted at IDP DAO layer.
     *
     * @param username Username value.
     * @param password Password value.
     * @return Array of properties.
     */
    private Property[] createBasicAuthPropertiesWithPlainValues(String username, String password) {

        Property[] properties = new Property[3];

        // Auth mode.
        Property authMode = new Property();
        authMode.setName(SCIM2ProvisioningConnectorConstants.SCIM2_AUTHENTICATION_MODE);
        authMode.setValue(AuthenticationType.BASIC.getValue());
        properties[0] = authMode;

        // Username.
        Property usernameProperty = new Property();
        usernameProperty.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME);
        usernameProperty.setValue(username);
        usernameProperty.setConfidential(true);
        properties[1] = usernameProperty;

        // Password.
        Property passwordProperty = new Property();
        passwordProperty.setName(SCIM2ProvisioningConnectorConstants.SCIM2_PASSWORD);
        passwordProperty.setValue(password);
        passwordProperty.setConfidential(true);
        properties[2] = passwordProperty;

        return properties;
    }

    /**
     * Helper method to create BEARER authentication properties with plain values.
     * Properties are already decrypted at IDP DAO layer.
     *
     * @param accessToken Access token value.
     * @return Array of properties.
     */
    private Property[] createBearerAuthPropertiesWithPlainValues(String accessToken) {

        Property[] properties = new Property[2];

        // Auth mode.
        Property authMode = new Property();
        authMode.setName(SCIM2ProvisioningConnectorConstants.SCIM2_AUTHENTICATION_MODE);
        authMode.setValue(AuthenticationType.BEARER.getValue());
        properties[0] = authMode;

        // Access token.
        Property accessTokenProperty = new Property();
        accessTokenProperty.setName(SCIM2ProvisioningConnectorConstants.SCIM2_ACCESS_TOKEN);
        accessTokenProperty.setValue(accessToken);
        accessTokenProperty.setConfidential(true);
        properties[1] = accessTokenProperty;

        return properties;
    }

    /**
     * Helper method to create API_KEY authentication properties with plain values.
     * Properties are already decrypted at IDP DAO layer.
     *
     * @param header API key header name.
     * @param value API key value.
     * @return Array of properties.
     */
    private Property[] createApiKeyAuthPropertiesWithPlainValues(String header, String value) {

        Property[] properties = new Property[3];

        // Auth mode.
        Property authMode = new Property();
        authMode.setName(SCIM2ProvisioningConnectorConstants.SCIM2_AUTHENTICATION_MODE);
        authMode.setValue(AuthenticationType.API_KEY.getValue());
        properties[0] = authMode;

        // API key header.
        Property headerProperty = new Property();
        headerProperty.setName(SCIM2ProvisioningConnectorConstants.SCIM2_API_KEY_HEADER);
        headerProperty.setValue(header);
        headerProperty.setConfidential(false);
        properties[1] = headerProperty;

        // API key value.
        Property valueProperty = new Property();
        valueProperty.setName(SCIM2ProvisioningConnectorConstants.SCIM2_API_KEY_VALUE);
        valueProperty.setValue(value);
        valueProperty.setConfidential(true);
        properties[2] = valueProperty;

        return properties;
    }

    /**
     * Helper method to find a property by name.
     *
     * @param properties List of properties.
     * @param name Property name to find.
     * @return Property if found, null otherwise.
     */
    private Property findPropertyByName(List<Property> properties, String name) {

        if (properties == null) {
            return null;
        }

        for (Property property : properties) {
            if (property.getName().equals(name)) {
                return property;
            }
        }
        return null;
    }

    /**
     * Helper method to check if an option exists in options array.
     *
     * @param options Array of options.
     * @param option Option to check.
     * @return True if option exists, false otherwise.
     */
    private boolean containsOption(String[] options, String option) {

        if (options == null || option == null) {
            return false;
        }

        for (String opt : options) {
            if (option.equals(opt)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Helper method to invoke buildConnector method using reflection.
     *
     * @param properties Properties to pass to buildConnector.
     * @return AbstractOutboundProvisioningConnector instance.
     * @throws Exception If invocation fails.
     */
    private AbstractOutboundProvisioningConnector invokeBuildConnector(Property[] properties) throws Exception {

        Method buildConnectorMethod = SCIM2ProvisioningConnectorFactory.class
                .getDeclaredMethod("buildConnector", Property[].class);
        buildConnectorMethod.setAccessible(true);
        return (AbstractOutboundProvisioningConnector) buildConnectorMethod
                .invoke(scim2ProvisioningConnectorFactory, (Object) properties);
    }
}
