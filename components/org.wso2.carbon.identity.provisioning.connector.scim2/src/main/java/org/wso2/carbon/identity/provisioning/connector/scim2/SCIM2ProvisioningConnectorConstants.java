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

/**
 * This class contains the constants related to SCIM2.
 */
public class SCIM2ProvisioningConnectorConstants {

    private SCIM2ProvisioningConnectorConstants() {
    }

    public static final String SCIM_USER_EP = "scim-user-ep";
    public static final String SCIM_GROUP_EP = "scim-group-ep";
    public static final String SCIM_USERNAME = "scim-username";
    public static final String SCIM_PASSWORD = "scim-password";
    public static final String SCIM_USERSTORE_DOMAIN = "scim-user-store-domain";
    public static final String DEFAULT_SCIM_DIALECT = "urn:scim:schemas:core:2.0";

    public static final String SCIM_ENABLE_PASSWORD_PROVISIONING = "scim-enable-pwd-provisioning";
    public static final String SCIM_DEFAULT_PASSWORD = "scim-default-pwd";

    public static final String DEFAULT = "default";
    public static final String ATTRIBUTE_TYPE = ".type";
    public static final String ATTRIBUTE_VALUE = ".value";
}
