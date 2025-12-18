/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

        Property username = new Property();
        username.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME);
        username.setDisplayName("Username");
        username.setDisplayOrder(1);
        username.setRequired(true);
        username.setType("string");

        Property userPassword = new Property();
        userPassword.setName(SCIM2ProvisioningConnectorConstants.SCIM2_PASSWORD);
        userPassword.setDisplayName("Password");
        userPassword.setConfidential(true);
        userPassword.setDisplayOrder(2);
        userPassword.setRequired(true);
        userPassword.setType("string");

        Property userEndpoint = new Property();
        userEndpoint.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USER_EP);
        userEndpoint.setDisplayName("User Endpoint");
        userEndpoint.setDisplayOrder(3);
        userEndpoint.setRequired(true);
        userEndpoint.setType("string");

        Property groupEndpoint = new Property();
        groupEndpoint.setName(SCIM2ProvisioningConnectorConstants.SCIM2_GROUP_EP);
        groupEndpoint.setDisplayName("Group Endpoint");
        groupEndpoint.setDisplayOrder(4);
        groupEndpoint.setType("string");
        groupEndpoint.setRequired(false);

        Property userStoreDomain = new Property();
        userStoreDomain.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USERSTORE_DOMAIN);
        userStoreDomain.setDisplayName("User Store Domain");
        userStoreDomain.setDisplayOrder(5);
        userStoreDomain.setRequired(false);
        userStoreDomain.setType("string");

        Property passwordProvisioning = new Property();
        passwordProvisioning.setName(SCIM2ProvisioningConnectorConstants.SCIM2_ENABLE_PASSWORD_PROVISIONING);
        passwordProvisioning.setDisplayName("Enable Password Provisioning");
        passwordProvisioning.setDescription("Enable User password provisioning to a SCIM2 domain");
        passwordProvisioning.setDisplayOrder(6);
        passwordProvisioning.setRequired(false);
        passwordProvisioning.setType("boolean");
        passwordProvisioning.setDefaultValue("true");

        SubProperty defaultPassword = new SubProperty();
        defaultPassword.setName(SCIM2ProvisioningConnectorConstants.SCIM2_DEFAULT_PASSWORD);
        defaultPassword.setDisplayName("Default Password");
        defaultPassword.setDisplayOrder(7);
        defaultPassword.setRequired(false);
        defaultPassword.setType("string");
        defaultPassword.setConfidential(true);
        passwordProvisioning.setSubProperties(new SubProperty[] {defaultPassword});

        properties.add(username);
        properties.add(userPassword);
        properties.add(userEndpoint);
        properties.add(groupEndpoint);
        properties.add(userStoreDomain);
        properties.add(passwordProvisioning);

        return properties;
    }
}
