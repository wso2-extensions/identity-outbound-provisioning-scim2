/*
* Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* WSO2 Inc. licenses this file to you under the Apache License,
* Version 2.0 (the "License"); you may not use this file except
* in compliance with the License.
* you may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/
package org.wso2.carbon.identity.provisioning.connector.scim2.test;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.provisioning.connector.scim2.util.SCIMClaimResolver;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.schema.SCIMSchemaDefinitions;

import static org.mockito.MockitoAnnotations.initMocks;

public class SCIMClaimResolverTest {

    private SCIMClaimResolver scimClaimResolver;
    private IdentitySCIMManager identitySCIMManager;
    private UserManager userManager;

    @BeforeMethod
    public void setUp() throws Exception {

        scimClaimResolver = new SCIMClaimResolver();
        identitySCIMManager = Mockito.mock(IdentitySCIMManager.class);
        userManager = Mockito.mock(UserManager.class);
        initMocks(this);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testGetResourceSchemaForGroup() throws Exception {

        SCIMClaimResolver s = Mockito.spy(scimClaimResolver);
        java.lang.reflect.Method method = SCIMClaimResolver.class.getDeclaredMethod("getResourceSchema", int.class);
        method.setAccessible(true);
        SCIMResourceTypeSchema schema = (SCIMResourceTypeSchema) method.invoke(s, 2);
        Assert.assertEquals(schema, SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA);
    }

    @Test
    public void testGetResourceSchemaForUser() throws Exception {

        SCIMClaimResolver s = Mockito.spy(scimClaimResolver);
        try (MockedStatic<IdentitySCIMManager> mockedStatic = Mockito.mockStatic(IdentitySCIMManager.class)) {
            mockedStatic.when(IdentitySCIMManager::getInstance).thenReturn(identitySCIMManager);
            Mockito.when(identitySCIMManager.getUserManager()).thenReturn(userManager);

            java.lang.reflect.Method method = SCIMClaimResolver.class.getDeclaredMethod("getResourceSchema", int.class);
            method.setAccessible(true);
            SCIMResourceTypeSchema expectedSchema = (SCIMResourceTypeSchema) method.invoke(s, 1);
            SCIMResourceTypeSchema actualSchema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
            Assert.assertEquals(actualSchema.getSchemasList(), expectedSchema.getSchemasList(),
                    "Expected and actual SCIM resource schemas for user do not match.");
            Assert.assertEquals(actualSchema.getAttributesList(), expectedSchema.getAttributesList(),
                    "Expected and actual SCIM resource attributes for user do not match.");
        }
    }
}
