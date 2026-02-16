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

package org.wso2.carbon.identity.provisioning.connector.scim2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.annotation.bundle.Capability;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.SubProperty;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.scim2.util.AuthenticationType;

import java.util.ArrayList;
import java.util.List;

/**
 * This class creates the SCIM2 connection factory.
 */
@Capability(
        namespace = "osgi.service",
        attribute = {
                "objectClass=org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory",
                "service.scope=singleton"
        }
)
public class SCIM2ProvisioningConnectorFactory extends AbstractProvisioningConnectorFactory {

    public static final String SCIM2 = "SCIM2";
    private static final Log log = LogFactory.getLog(SCIM2ProvisioningConnectorFactory.class);

    /**
     * Initializes the SCIM2 provisioning connector.
     *
     * @param provisioningProperties            Properties of the SCIM2 provisioning connector.
     * @return AbstractOutboundProvisioningConnector
     * @throws IdentityProvisioningException    Error when initializing the SCIM2 provisioning connector.
     */
    @Override
    protected AbstractOutboundProvisioningConnector buildConnector(Property[] provisioningProperties)
            throws IdentityProvisioningException {

        SCIM2ProvisioningConnector scimProvisioningConnector = new SCIM2ProvisioningConnector();
        scimProvisioningConnector.init(provisioningProperties);

        if (log.isDebugEnabled()) {
            log.debug("Created new connector of type : " + SCIM2);
        }
        return scimProvisioningConnector;
    }

    /**
     * Returns the connectorType.
     *
     * @return connectorType
     */
    @Override
    public String getConnectorType() {
        return SCIM2;
    }

    /**
     * Populates the configuration properties.
     *
     * @return property list
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> properties = new ArrayList<Property>();

        // Authentication Mode Property with SubProperties.
        Property authMode = new Property();
        authMode.setName(SCIM2ProvisioningConnectorConstants.SCIM2_AUTHENTICATION_MODE);
        authMode.setDisplayName("Authentication Mode");
        authMode.setDisplayOrder(1);
        authMode.setRequired(true);
        authMode.setType("enum");
        authMode.setOptions(new String[]{
                AuthenticationType.BASIC.getValue(),
                AuthenticationType.BEARER.getValue(),
                AuthenticationType.API_KEY.getValue(),
                AuthenticationType.NONE.getValue()
        });
        authMode.setDefaultValue(AuthenticationType.BASIC.getValue());

        // BASIC auth subproperties
        Property username = new Property();
        username.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME);
        username.setDisplayName("Username");
        username.setDisplayOrder(2);
        username.setRequired(false);
        username.setType("string");

        Property userPassword = new Property();
        userPassword.setName(SCIM2ProvisioningConnectorConstants.SCIM2_PASSWORD);
        userPassword.setDisplayName("Password");
        userPassword.setConfidential(true);
        userPassword.setDisplayOrder(3);
        username.setRequired(false);
        userPassword.setType("string");
        userPassword.setConfidential(true);

        // BEARER auth subproperty
        Property accessToken = new Property();
        accessToken.setName(SCIM2ProvisioningConnectorConstants.SCIM2_ACCESS_TOKEN);
        accessToken.setDisplayName("Access Token");
        accessToken.setDisplayOrder(4);
        accessToken.setRequired(false);
        accessToken.setType("string");
        accessToken.setConfidential(true);

        // API_KEY auth subproperties
        Property apiKeyHeader = new Property();
        apiKeyHeader.setName(SCIM2ProvisioningConnectorConstants.SCIM2_API_KEY_HEADER);
        apiKeyHeader.setDisplayName("API Key Header Name");
        apiKeyHeader.setDisplayOrder(5);
        apiKeyHeader.setRequired(false);
        apiKeyHeader.setType("string");
        apiKeyHeader.setConfidential(false);

        Property apiKeyValue = new Property();
        apiKeyValue.setName(SCIM2ProvisioningConnectorConstants.SCIM2_API_KEY_VALUE);
        apiKeyValue.setDisplayName("API Key Value");
        apiKeyValue.setDisplayOrder(6);
        apiKeyValue.setRequired(false);
        apiKeyValue.setType("string");
        apiKeyValue.setConfidential(true);

        Property userEndpoint = new Property();
        userEndpoint.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USER_EP);
        userEndpoint.setDisplayName("User Endpoint");
        userEndpoint.setDisplayOrder(7);
        userEndpoint.setRequired(true);
        userEndpoint.setType("string");

        Property groupEndpoint = new Property();
        groupEndpoint.setName(SCIM2ProvisioningConnectorConstants.SCIM2_GROUP_EP);
        groupEndpoint.setDisplayName("Group Endpoint");
        groupEndpoint.setDisplayOrder(8);
        groupEndpoint.setType("string");
        groupEndpoint.setRequired(false);

        Property userStoreDomain = new Property();
        userStoreDomain.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USERSTORE_DOMAIN);
        userStoreDomain.setDisplayName("User Store Domain");
        userStoreDomain.setDisplayOrder(9);
        userStoreDomain.setRequired(false);
        userStoreDomain.setType("string");

        Property passwordProvisioning = new Property();
        passwordProvisioning.setName(SCIM2ProvisioningConnectorConstants.SCIM2_ENABLE_PASSWORD_PROVISIONING);
        passwordProvisioning.setDisplayName("Enable Password Provisioning");
        passwordProvisioning.setDescription("Enable User password provisioning to a SCIM2 domain");
        passwordProvisioning.setDisplayOrder(10);
        passwordProvisioning.setRequired(false);
        passwordProvisioning.setType("boolean");
        passwordProvisioning.setDefaultValue("true");

        SubProperty defaultPassword = new SubProperty();
        defaultPassword.setName(SCIM2ProvisioningConnectorConstants.SCIM2_DEFAULT_PASSWORD);
        defaultPassword.setDisplayName("Default Password");
        defaultPassword.setDisplayOrder(11);
        defaultPassword.setRequired(false);
        defaultPassword.setType("string");
        defaultPassword.setConfidential(true);
        passwordProvisioning.setSubProperties(new SubProperty[] {defaultPassword});

        properties.add(authMode);
        properties.add(username);
        properties.add(userPassword);
        properties.add(accessToken);
        properties.add(apiKeyHeader);
        properties.add(apiKeyValue);
        properties.add(userEndpoint);
        properties.add(groupEndpoint);
        properties.add(userStoreDomain);
        properties.add(passwordProvisioning);

        return properties;
    }
}
