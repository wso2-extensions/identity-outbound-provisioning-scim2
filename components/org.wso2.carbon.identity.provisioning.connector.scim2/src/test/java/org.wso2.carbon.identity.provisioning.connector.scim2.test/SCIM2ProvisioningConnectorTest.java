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
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.IObjectFactory;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningEntityType;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnector;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorConstants;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;
import org.wso2.scim2.client.ProvisioningClient;
import org.wso2.scim2.client.SCIMProvider;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@PrepareForTest({PatchOperation.class, SCIM2ProvisioningConnector.class, SCIMProvider.class})
public class SCIM2ProvisioningConnectorTest extends PowerMockTestCase {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {

        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    private SCIM2ProvisioningConnector sCIM2ProvisioningConnector;
    private ProvisioningClient provisioningClient;
    private SCIMProvider scimProvider;

    @BeforeMethod
    public void setUp() throws Exception {

        sCIM2ProvisioningConnector = new SCIM2ProvisioningConnector();
        scimProvider = Mockito.mock(SCIMProvider.class);
        provisioningClient = Mockito.mock(ProvisioningClient.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testGetConnectorType() throws Exception {

        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "getUserStoreDomainName");
    }

    @Test
    public void testCreateUser() throws Exception {

        PowerMockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");
        sCIM2ProvisioningConnector.init(new Property[0]);
        PowerMockito.whenNew(ProvisioningClient.class).withArguments(Mockito.anyObject(), Mockito.anyObject(),
                Mockito.anyObject()).thenReturn(provisioningClient);
        PowerMockito.whenNew(SCIMProvider.class).withNoArguments().thenReturn(scimProvider);
        Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
        List<String> value = new ArrayList<String>();
        value.add("testUser");
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.PASSWORD_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.GROUP_CLAIM_URI,null,null,
                false), null);
        ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER, ProvisioningOperation.POST,
                attributes);
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "createUser",userEntity);
    }

    @Test
    public void testUpdateUser() throws Exception {

        PowerMockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");
        sCIM2ProvisioningConnector.init(new Property[0]);
        PowerMockito.whenNew(ProvisioningClient.class).withArguments(Mockito.anyObject(), Mockito.anyObject(),
                Mockito.anyObject()).thenReturn(provisioningClient);
        PowerMockito.whenNew(SCIMProvider.class).withNoArguments().thenReturn(scimProvider);
        Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
        List<String> value = new ArrayList<String>();
        value.add("testUser");
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.PASSWORD_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.GROUP_CLAIM_URI,null,null,
                false), null);
        ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER, ProvisioningOperation.PUT,
                attributes);
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "updateUser",userEntity,ProvisioningOperation.PUT);
    }

    @Test
    public void testDeleteUser() throws Exception {

        PowerMockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");
        sCIM2ProvisioningConnector.init(new Property[0]);
        PowerMockito.whenNew(ProvisioningClient.class).withArguments(Mockito.anyObject(), Mockito.anyObject(),
                Mockito.anyObject()).thenReturn(provisioningClient);
        PowerMockito.whenNew(SCIMProvider.class).withNoArguments().thenReturn(scimProvider);
        Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
        List<String> value = new ArrayList<String>();
        value.add("testUser");
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.PASSWORD_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.GROUP_CLAIM_URI,null,null,
                false), null);
        ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER, ProvisioningOperation.
                DELETE, attributes);
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "deleteUser",userEntity);
    }

    @Test
    public void testCreateGroup() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        PowerMockito.whenNew(ProvisioningClient.class).withArguments(Mockito.anyObject(), Mockito.anyObject(),
                Mockito.anyObject()).thenReturn(provisioningClient);
        PowerMockito.whenNew(SCIMProvider.class).withNoArguments().thenReturn(scimProvider);
        Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
        List<String> value = new ArrayList<String>();
        value.add("testGroup");
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.GROUP_CLAIM_URI,null,null,
                false), value);
        ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP, ProvisioningOperation.
                POST,attributes);
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "createGroup",groupEntity);
    }

    @Test
    public void testUpdateGroup() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        PowerMockito.whenNew(ProvisioningClient.class).withArguments(Mockito.anyObject(), Mockito.anyObject(),
                Mockito.anyObject()).thenReturn(provisioningClient);
        PowerMockito.whenNew(SCIMProvider.class).withNoArguments().thenReturn(scimProvider);
        Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
        List<String> value = new ArrayList<String>();
        value.add("testGroup");
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.OLD_GROUP_NAME_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.NEW_GROUP_NAME_CLAIM_URI,null,null,
                false), value);
        ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP, ProvisioningOperation.
                PUT,attributes);
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "updateGroup",groupEntity);
    }

    @Test
    public void testDeleteGroup() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        PowerMockito.whenNew(ProvisioningClient.class).withArguments(Mockito.anyObject(), Mockito.anyObject(),
                Mockito.anyObject()).thenReturn(provisioningClient);
        PowerMockito.whenNew(SCIMProvider.class).withNoArguments().thenReturn(scimProvider);
        Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
        List<String> value = new ArrayList<String>();
        value.add("testGroup");
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.GROUP_CLAIM_URI,null,null,
                false), value);
        ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP, ProvisioningOperation.
                DELETE,attributes);
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "deleteGroup",groupEntity);
    }

    @Test
    public void testPopulateSCIMProvider() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        Property property = new Property();
        property.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME);
        property.setValue("testUser");
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "populateSCIMProvider",property,
                SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME);
    }

    @Test
    public void testSetPassword() throws Exception {

        User user = new User();
        user.setUserName("testUser");
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "setPassword",user, "testPassword");
    }

    @Test
    public void testSetUserPassword() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        User user = new User();
        user.setUserName("testUser");
        Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
        List<String> value = new ArrayList<String>();
        value.add("testUser");
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.PASSWORD_CLAIM_URI,null,null,
                false), value);
        attributes.put(ClaimMapping.build(IdentityProvisioningConstants.GROUP_CLAIM_URI,null,null,
                false), null);
        ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER, ProvisioningOperation.
                POST, attributes);
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "setUserPassword",user, userEntity);
    }

    @Test
    public void testSetMember() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        Group group = new Group();
        group.setDisplayName("testGroup");
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "setMember",group, "testUser");
    }

    @Test
    public void testSetGroupMembers() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        Group group = new Group();
        group.setDisplayName("testGroup");
        List<String> userList = new ArrayList<>();
        userList.add("testUser");
        Whitebox.invokeMethod(sCIM2ProvisioningConnector, "setGroupMembers",group, userList);
    }
}
