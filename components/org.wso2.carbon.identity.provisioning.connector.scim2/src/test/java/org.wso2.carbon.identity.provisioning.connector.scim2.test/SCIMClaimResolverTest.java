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

import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.provisioning.connector.scim2.util.SCIMClaimResolver;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMSchemaDefinitions;

import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;

@PrepareForTest(IdentitySCIMManager.class)
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
    public void testGetResourceSchemaforGroup() throws Exception {

        SCIMClaimResolver s = PowerMockito.spy(scimClaimResolver);
        Assert.assertEquals(Whitebox.invokeMethod(s, "getResourceSchema", 2),
                SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA);
    }

    @Test
    public void testGetResourceSchemaforUser() throws Exception {

        SCIMClaimResolver s = PowerMockito.spy(scimClaimResolver);
        PowerMockito.mockStatic(IdentitySCIMManager.class);
        when(IdentitySCIMManager.getInstance()).thenReturn(identitySCIMManager);
        when(identitySCIMManager.getUserManager()).thenReturn(userManager);
        Assert.assertEquals(Whitebox.invokeMethod(s, "getResourceSchema", 1),
                SCIMResourceSchemaManager.getInstance().getUserResourceSchema());
    }
}
