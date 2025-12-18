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

import org.mockito.MockedConstruction;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
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
import org.wso2.scim2.client.ProvisioningClient;
import org.wso2.scim2.client.SCIMProvider;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SCIM2ProvisioningConnectorTest {

    private SCIM2ProvisioningConnector sCIM2ProvisioningConnector;
    private SCIMProvider scimProvider;

    @BeforeMethod
    public void setUp() throws Exception {

        sCIM2ProvisioningConnector = new SCIM2ProvisioningConnector();
        scimProvider = Mockito.mock(SCIMProvider.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testGetConnectorType() throws Exception {

        Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("getUserStoreDomainName");
        method.setAccessible(true);
        method.invoke(sCIM2ProvisioningConnector);
    }

    @Test
    public void testCreateUser() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");
            sCIM2ProvisioningConnector.init(new Property[0]);
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
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("createUser", ProvisioningEntity.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity);
        }
    }

    @Test
    public void testUpdateUser() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");
            sCIM2ProvisioningConnector.init(new Property[0]);
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
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateUser", ProvisioningEntity.class,
                    ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity, ProvisioningOperation.PUT);
        }
    }

    @Test
    public void testDeleteUser() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");
            sCIM2ProvisioningConnector.init(new Property[0]);
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
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("deleteUser", ProvisioningEntity.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity);
        }
    }

    @Test
    public void testCreateGroup() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            sCIM2ProvisioningConnector.init(new Property[0]);
            Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
            List<String> value = new ArrayList<String>();
            value.add("testGroup");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.GROUP_CLAIM_URI,null,null,
                    false), value);
            ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP, ProvisioningOperation.
                    POST,attributes);
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("createGroup", ProvisioningEntity.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, groupEntity);
        }
    }

    @Test
    public void testUpdateGroup() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            sCIM2ProvisioningConnector.init(new Property[0]);
            Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
            List<String> value = new ArrayList<String>();
            value.add("testGroup");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.OLD_GROUP_NAME_CLAIM_URI,null,null,
                    false), value);
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.NEW_GROUP_NAME_CLAIM_URI,null,null,
                    false), value);
            ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP, ProvisioningOperation.
                    PUT,attributes);
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateGroup", ProvisioningEntity.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, groupEntity);
        }
    }

    @Test
    public void testDeleteGroup() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            sCIM2ProvisioningConnector.init(new Property[0]);
            Map<ClaimMapping, List<String>> attributes = new HashMap<ClaimMapping, List<String>>();
            List<String> value = new ArrayList<String>();
            value.add("testGroup");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.GROUP_CLAIM_URI,null,null,
                    false), value);
            ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP, ProvisioningOperation.
                    DELETE,attributes);
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("deleteGroup", ProvisioningEntity.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, groupEntity);
        }
    }

    @Test
    public void testPopulateSCIMProvider() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        Property property = new Property();
        property.setName(SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME);
        property.setValue("testUser");
        Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("populateSCIMProvider", Property.class,
                String.class);
        method.setAccessible(true);
        method.invoke(sCIM2ProvisioningConnector, property,
                SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME);
    }

    @Test
    public void testSetPassword() throws Exception {

        User user = new User();
        user.setUserName("testUser");
        Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("setPassword", User.class, String.class);
        method.setAccessible(true);
        method.invoke(sCIM2ProvisioningConnector, user, "testPassword");
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
        Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("setUserPassword", User.class,
                ProvisioningEntity.class);
        method.setAccessible(true);
        method.invoke(sCIM2ProvisioningConnector, user, userEntity);
    }

    @Test
    public void testSetMember() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        Group group = new Group();
        group.setDisplayName("testGroup");
        Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("setMember", Group.class, String.class);
        method.setAccessible(true);
        method.invoke(sCIM2ProvisioningConnector, group, "testUser");
    }

    @Test
    public void testSetGroupMembers() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);
        Group group = new Group();
        group.setDisplayName("testGroup");
        List<String> userList = new ArrayList<>();
        userList.add("testUser");
        Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("setGroupMembers", Group.class,
                List.class);
        method.setAccessible(true);
        method.invoke(sCIM2ProvisioningConnector, group, userList);
    }
}
