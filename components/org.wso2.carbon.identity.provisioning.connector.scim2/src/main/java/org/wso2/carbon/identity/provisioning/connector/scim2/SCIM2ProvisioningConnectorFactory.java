/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

public class SCIM2ProvisioningConnectorFactory extends AbstractProvisioningConnectorFactory {

    public static final String SCIM2 = "scim 2.0";
    private static final Log log = LogFactory.getLog(SCIM2ProvisioningConnectorFactory.class);

    @Override
    /**
     * @throws IdentityProvisioningException
     */
    protected SCIM2ProvisioningConnector buildConnector(Property[] provisioningProperties)
            throws IdentityProvisioningException {
        SCIM2ProvisioningConnector scimProvisioningConnector = new SCIM2ProvisioningConnector();
        scimProvisioningConnector.init(provisioningProperties);

        if (log.isDebugEnabled()) {
            log.debug("Created new connector of type : " + SCIM2);
        }
        return scimProvisioningConnector;
    }

    @Override
    public String getConnectorType() {
        return SCIM2;
    }

}
