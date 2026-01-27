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

package org.wso2.carbon.identity.provisioning.connector.scim2.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorConstants;
import org.wso2.scim2.util.SCIM2ClientConfig;

/**
 * Utility class to register SCIM2 client configurations from Identity configs.
 * Follows the pattern similar to IdentitySCIMManager#registerCharonConfig.
 */
public class SCIM2ClientConfigRegistrar {

    private static final Log log = LogFactory.getLog(SCIM2ClientConfigRegistrar.class);

    // Default values (aligned with SCIM2ClientConfig defaults).
    private static final int DEFAULT_HTTP_REQUEST_RETRY_COUNT = 1;
    private static final int DEFAULT_HTTP_READ_TIMEOUT_IN_MILLIS = 5000;
    private static final int DEFAULT_HTTP_CONNECTION_TIMEOUT_IN_MILLIS = 2000;
    private static final int DEFAULT_HTTP_CONNECTION_REQUEST_TIMEOUT_IN_MILLIS = 2000;
    private static final int DEFAULT_HTTP_CONNECTION_POOL_SIZE = 20;
    private static final int DEFAULT_NIO_THREAD_COUNT = 4;

    private SCIM2ClientConfigRegistrar() {
        // Private constructor to prevent instantiation.
    }

    /**
     * Registers SCIM2 client HTTP configurations from identity.xml.
     * This method reads configurations from IdentityUtil and registers them in SCIM2ClientConfig.
     * The registration pattern is inspired by IdentitySCIMManager#registerCharonConfig.
     */
    public static void registerClientConfig() {

        try {
            SCIM2ClientConfig clientConfig = SCIM2ClientConfig.getInstance();

            // Register retry configuration.
            // Retry count of 0 means no retries (only original request).
            // Retry count of N means original request + N retries.
            int retryCount = parseInt(IdentityUtil.getProperty(
                    SCIM2ProvisioningConnectorConstants.SCIM2_CLIENT_HTTP_RETRY_COUNT), DEFAULT_HTTP_REQUEST_RETRY_COUNT);
            clientConfig.registerRetryConfig(retryCount);

            // Register timeout configuration.
            int readTimeout = parseInt(IdentityUtil.getProperty(
                    SCIM2ProvisioningConnectorConstants.SCIM2_CLIENT_HTTP_READ_TIMEOUT), DEFAULT_HTTP_READ_TIMEOUT_IN_MILLIS);
            int connectionTimeout = parseInt(IdentityUtil.getProperty(
                    SCIM2ProvisioningConnectorConstants.SCIM2_CLIENT_HTTP_CONNECTION_TIMEOUT),
                    DEFAULT_HTTP_CONNECTION_TIMEOUT_IN_MILLIS);
            int connectionRequestTimeout = parseInt(IdentityUtil.getProperty(
                    SCIM2ProvisioningConnectorConstants.SCIM2_CLIENT_HTTP_CONNECTION_REQUEST_TIMEOUT),
                    DEFAULT_HTTP_CONNECTION_REQUEST_TIMEOUT_IN_MILLIS);
            clientConfig.registerTimeoutConfig(readTimeout, connectionTimeout, connectionRequestTimeout);

            // Register connection pool configuration.
            int poolSize = parseInt(IdentityUtil.getProperty(
                    SCIM2ProvisioningConnectorConstants.SCIM2_CLIENT_HTTP_CONNECTION_POOL_SIZE),
                    DEFAULT_HTTP_CONNECTION_POOL_SIZE);
            clientConfig.registerConnectionPoolConfig(poolSize);

            // Register NIO thread count configuration.
            int nioThreadCount = parseInt(IdentityUtil.getProperty(
                    SCIM2ProvisioningConnectorConstants.SCIM2_CLIENT_NIO_THREAD_COUNT),
                    DEFAULT_NIO_THREAD_COUNT);
            clientConfig.registerNioThreadCountConfig(nioThreadCount);

            if (log.isDebugEnabled()) {
                log.debug("Successfully registered SCIM2 client configurations from identity.xml");
            }
        } catch (Exception e) {
            log.error("Error registering SCIM2 client configurations. Using defaults.", e);
        }
    }

    /**
     * Parses an integer value from a string property.
     *
     * @param value String value to parse.
     * @param defaultValue Default value if parsing fails.
     * @return Parsed integer value or default.
     */
    private static int parseInt(String value, int defaultValue) {

        if (StringUtils.isNotBlank(value)) {
            try {
                return Integer.parseInt(value);
            } catch (NumberFormatException e) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Failed to parse integer value: %s. Using default: %d",
                            value, defaultValue), e);
                }
            }
        }
        return defaultValue;
    }
}
