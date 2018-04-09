/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.provisioning.connector.scim2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorFactory;

/**
 * @scr.component name=
 * "org.wso2.carbon.identity.provisioning.connector.scim2.internal.SCIM2ConnectorServiceComponent"
 * immediate="true"
 */
public class SCIM2ConnectorServiceComponent {
    private static Log log = LogFactory.getLog(SCIM2ConnectorServiceComponent.class);

    protected void activate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Activating SCIM2ConnectorServiceComponent");
        }

        try {
            SCIM2ProvisioningConnectorFactory scim2ProvisioningConnectorFactory = new
                    SCIM2ProvisioningConnectorFactory();
            context.getBundleContext().registerService(AbstractProvisioningConnectorFactory.class.getName(),
                    scim2ProvisioningConnectorFactory, null);
            if (log.isDebugEnabled()) {
                log.debug("SCIM2 Provisioning Connector bundle is activated");
            }
        } catch (Throwable e) {
            log.error(" Error while activating SCIM2 Provisioning Connector ", e);
        }
    }
}
