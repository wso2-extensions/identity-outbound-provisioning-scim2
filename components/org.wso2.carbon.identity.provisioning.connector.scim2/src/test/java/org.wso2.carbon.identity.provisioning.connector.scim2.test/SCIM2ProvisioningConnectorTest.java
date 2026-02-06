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

package org.wso2.carbon.identity.provisioning.connector.scim2.test;

import org.json.JSONObject;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningEntityType;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnector;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorConstants;
import org.wso2.carbon.identity.provisioning.connector.scim2.util.SCIM2ConnectorUtil;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;
import org.wso2.scim2.client.ProvisioningClient;
import org.wso2.scim2.client.SCIMProvider;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.testng.Assert.*;

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
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
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
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
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
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
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
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
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
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
            value.add("testGroup");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.OLD_GROUP_NAME_CLAIM_URI,null,null,
                    false), value);
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.NEW_GROUP_NAME_CLAIM_URI,null,null,
                    false), value);
            ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP, ProvisioningOperation.
                    PUT,attributes);
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateGroup", ProvisioningEntity.class,
                    ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, groupEntity, ProvisioningOperation.PUT);
        }
    }

    @Test
    public void testPatchGroupDisplayName() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            sCIM2ProvisioningConnector.init(new Property[0]);
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> oldGroupName = new ArrayList<>();
            oldGroupName.add("oldGroupName");
            List<String> newGroupName = new ArrayList<>();
            newGroupName.add("newGroupName");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.OLD_GROUP_NAME_CLAIM_URI,
                    null, null,
                    false), oldGroupName);
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.NEW_GROUP_NAME_CLAIM_URI,
                    null, null,
                    false), newGroupName);
            ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP,
                    ProvisioningOperation.PATCH, attributes);
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateGroup",
                    ProvisioningEntity.class, ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, groupEntity, ProvisioningOperation.PATCH);
        }
    }

    @Test
    public void testDeleteGroup() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            sCIM2ProvisioningConnector.init(new Property[0]);
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
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

    @Test
    public void testPatchUser() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class)) {
            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");
            sCIM2ProvisioningConnector.init(new Property[0]);
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
            value.add("testUser");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI, null, null,
                    false), value);

            List<String> displayNameValue = new ArrayList<String>();
            displayNameValue.add("Test User Updated");
            attributes.put(ClaimMapping.build("urn:ietf:params:scim:schemas:core:2.0:User:displayName", null, null,
                    false), displayNameValue);

            ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER,
                    ProvisioningOperation.PATCH, attributes);
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateUser", ProvisioningEntity.class,
                    ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity, ProvisioningOperation.PATCH);
        }
    }

    @Test
    public void testBuildPatchOperationsWithAllAttributeTypes() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create user with all attribute types: core simple, core complex, core multi-valued, extension simple, extension complex.
        User user = new User();
        user.setUserName("testUser");

        // Core simple attributes.
        SimpleAttribute displayName = new SimpleAttribute("displayName", "John Doe");
        SimpleAttribute nickName = new SimpleAttribute("nickName", "JD");
        user.setAttribute(displayName);
        user.setAttribute(nickName);

        // Core complex attribute (name).
        org.wso2.charon3.core.attributes.ComplexAttribute nameAttr =
                new org.wso2.charon3.core.attributes.ComplexAttribute("name");
        SimpleAttribute givenName = new SimpleAttribute("givenName", "John");
        SimpleAttribute familyName = new SimpleAttribute("familyName", "Doe");
        nameAttr.setSubAttribute(givenName);
        nameAttr.setSubAttribute(familyName);
        user.setAttribute(nameAttr);

        // Core multi-valued attribute (emails).
        org.wso2.charon3.core.attributes.MultiValuedAttribute emails =
                new org.wso2.charon3.core.attributes.MultiValuedAttribute("emails");
        org.wso2.charon3.core.attributes.ComplexAttribute email1 =
                new org.wso2.charon3.core.attributes.ComplexAttribute("emails");
        email1.setSubAttribute(new SimpleAttribute("value", "john@example.com"));
        email1.setSubAttribute(new SimpleAttribute("type", "work"));
        emails.setAttributeValue(email1);
        user.setAttribute(emails);

        // Enterprise extension simple attributes.
        org.wso2.charon3.core.attributes.ComplexAttribute enterpriseExt =
                new org.wso2.charon3.core.attributes.ComplexAttribute(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
        SimpleAttribute department = new SimpleAttribute("department", "Engineering");
        SimpleAttribute employeeNumber = new SimpleAttribute("employeeNumber", "EMP001");
        enterpriseExt.setSubAttribute(department);
        enterpriseExt.setSubAttribute(employeeNumber);

        // Enterprise extension complex attribute (manager).
        org.wso2.charon3.core.attributes.ComplexAttribute manager =
                new org.wso2.charon3.core.attributes.ComplexAttribute("manager");
        manager.setSubAttribute(new SimpleAttribute("value", "manager-id-123"));
        manager.setSubAttribute(new SimpleAttribute("displayName", "Manager Name"));
        enterpriseExt.setSubAttribute(manager);
        user.setAttribute(enterpriseExt);

        // Build patch operations.
        List<PatchOperation> patchOps = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify operations created.
        assertNotNull(patchOps);
        assertTrue(patchOps.size() > 0, "Should generate patch operations");

        // Verify core simple attributes.
        assertTrue(patchOps.stream().anyMatch(op -> "displayName".equals(op.getPath()) &&
                "John Doe".equals(op.getValues())), "Should have displayName");
        assertTrue(patchOps.stream().anyMatch(op -> "nickName".equals(op.getPath()) &&
                "JD".equals(op.getValues())), "Should have nickName");

        // Verify core complex attribute.
        Optional<PatchOperation> nameOp = patchOps.stream()
                .filter(op -> "name".equals(op.getPath())).findFirst();
        assertTrue(nameOp.isPresent(), "Should have name operation");
        assertNotNull(nameOp.get().getValues(), "Name value should not be null");

        // Verify core multi-valued attribute.
        Optional<PatchOperation> emailsOp = patchOps.stream()
                .filter(op -> "emails".equals(op.getPath())).findFirst();
        assertTrue(emailsOp.isPresent(), "Should have emails operation");
        assertNotNull(emailsOp.get().getValues(), "Emails value should not be null");

        // Verify extension simple attributes use full schema path.
        assertTrue(patchOps.stream().anyMatch(op ->
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department".equals(op.getPath()) &&
                "Engineering".equals(op.getValues())), "Should have department with full path");
        assertTrue(patchOps.stream().anyMatch(op ->
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber".equals(op.getPath()) &&
                "EMP001".equals(op.getValues())), "Should have employeeNumber with full path");

        // Verify extension complex attribute.
        Optional<PatchOperation> managerOp = patchOps.stream()
                .filter(op -> "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager".equals(op.getPath()))
                .findFirst();
        assertTrue(managerOp.isPresent(), "Should have manager operation");
        Object managerValue = managerOp.get().getValues();
        assertNotNull(managerValue, "Manager value should not be null");
        assertTrue(managerValue instanceof JSONObject, "Manager should be JSONObject");
        JSONObject managerJson = (JSONObject) managerValue;
        assertEquals(managerJson.getString("value"), "manager-id-123");
        assertEquals(managerJson.getString("displayName"), "Manager Name");

        // Verify all operations are REPLACE with proper structure.
        for (PatchOperation op : patchOps) {
            assertNotNull(op.getOperation(), "Operation type should not be null");
            assertNotNull(op.getPath(), "Path should not be null");
            assertEquals(op.getOperation(), SCIMConstants.OperationalConstants.REPLACE,
                    "All operations should be REPLACE");
        }

        // Verify metadata attributes are excluded.
        assertFalse(patchOps.stream().anyMatch(op -> SCIMConstants.CommonSchemaConstants.ID.equals(op.getPath())),
                "ID should not be in patch operations");
        assertFalse(patchOps.stream().anyMatch(op -> SCIMConstants.CommonSchemaConstants.META.equals(op.getPath())),
                "Meta should not be in patch operations");
        assertFalse(patchOps.stream().anyMatch(op -> SCIMConstants.CommonSchemaConstants.SCHEMAS.equals(op.getPath())),
                "Schemas should not be in patch operations");
        assertFalse(patchOps.stream().anyMatch(op -> SCIMConstants.UserSchemaConstants.PASSWORD.equals(op.getPath())),
                "Password should not be in patch operations");

        // Verify extension path format is schema:attributeName (not just schema URI).
        patchOps.stream()
                .filter(op -> op.getPath() != null && op.getPath().contains("enterprise"))
                .forEach(op -> assertFalse(op.getPath().equals("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"),
                        "Extension paths should include :attributeName, not just schema URI"));
    }

    @Test
    public void testBuildPatchOperationsWithEmptyUser() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create an empty User object.
        User emptyUser = new User();
        emptyUser.setUserName("testUser");

        // Call the public static method from SCIM2ConnectorUtil.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(emptyUser);

        // Should return some operations (at least userName).
        assertNotNull(patchOperations);
    }

    @Test
    public void testIsExtensionSchema() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Test valid extension schema URIs.
        Boolean isEnterpriseExtension = SCIM2ConnectorUtil.isExtensionSchema(
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");
        assertTrue(isEnterpriseExtension, "Enterprise extension schema should be recognized");

        Boolean isCustomExtension = SCIM2ConnectorUtil.isExtensionSchema(SCIMCommonUtils.getCustomSchemaURI());
        assertTrue(isCustomExtension, "Custom extension schema should be recognized");

        // Test non-extension schema attributes.
        Boolean isUserName = SCIM2ConnectorUtil.isExtensionSchema("userName");
        assertFalse(isUserName, "Core attribute should not be recognized as extension");

        Boolean isDisplayName = SCIM2ConnectorUtil.isExtensionSchema("displayName");
        assertFalse(isDisplayName, "Core attribute should not be recognized as extension");

        Boolean isNull = SCIM2ConnectorUtil.isExtensionSchema(null);
        assertFalse(isNull, "Null should not be recognized as extension");
    }

    @Test
    public void testUpdateUserWithPatchEnabledConfig() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class,
                (mock, context) -> {
                    // Verify that provisionPatchUser is called (not provisionUpdateUser).
                });
             MockedStatic<IdentityUtil> identityUtilMock = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentitySCIMManager> identitySCIMManagerMock = Mockito.mockStatic(IdentitySCIMManager.class);
             MockedStatic<AttributeMapper> attributeMapperMock = Mockito.mockStatic(AttributeMapper.class)) {

            // Mock IdentitySCIMManager and UserManager.
            IdentitySCIMManager mockSCIMManager = Mockito.mock(IdentitySCIMManager.class);
            UserManager mockUserManager = Mockito.mock(UserManager.class);
            identitySCIMManagerMock.when(IdentitySCIMManager::getInstance).thenReturn(mockSCIMManager);
            Mockito.when(mockSCIMManager.getUserManager()).thenReturn(mockUserManager);

            // Mock AttributeMapper to return a User object.
            User mockUser = new User();
            mockUser.setUserName("testUser");
            attributeMapperMock.when(() -> AttributeMapper.constructSCIMObjectFromAttributes(
                    Mockito.any(UserManager.class), Mockito.anyMap(), Mockito.anyInt()))
                    .thenReturn(mockUser);

            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");

            // Configure with PATCH enabled for updates via identity.xml.
            identityUtilMock.when(() -> IdentityUtil.getProperty(
                    IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES)).thenReturn("true");

            sCIM2ProvisioningConnector.init(new Property[0]);

            // Inject mocked scimProvider using reflection.
            java.lang.reflect.Field scimProviderField = SCIM2ProvisioningConnector.class.getDeclaredField("scimProvider");
            scimProviderField.setAccessible(true);
            scimProviderField.set(sCIM2ProvisioningConnector, scimProvider);

            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
            value.add("testUser");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI,
                    IdentityProvisioningConstants.USERNAME_CLAIM_URI, null, false), value);
            List<String> displayNameValue = new ArrayList<>();
            displayNameValue.add("Test User");
            String displayNameUri = "urn:ietf:params:scim:schemas:core:2.0:User:displayName";
            attributes.put(ClaimMapping.build(displayNameUri, displayNameUri, null, false), displayNameValue);

            ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER,
                    ProvisioningOperation.PUT, attributes);

            // Use reflection to call updateUser with PUT operation.
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateUser",
                    ProvisioningEntity.class, ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity, ProvisioningOperation.PUT);

            // Verify that provisionPatchUser was called (because PATCH is enabled).
            assertEquals(mocked.constructed().size(), 1, "ProvisioningClient should be constructed once");
            ProvisioningClient client = mocked.constructed().get(0);
            Mockito.verify(client, Mockito.times(1)).provisionPatchUser();
            Mockito.verify(client, Mockito.never()).provisionUpdateUser();
        }
    }

    @Test
    public void testUpdateUserWithPatchDisabledConfig() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class,
                (mock, context) -> {
                    // Verify that provisionUpdateUser is called (not provisionPatchUser).
                });
             MockedStatic<IdentityUtil> identityUtilMock = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentitySCIMManager> identitySCIMManagerMock = Mockito.mockStatic(IdentitySCIMManager.class);
             MockedStatic<AttributeMapper> attributeMapperMock = Mockito.mockStatic(AttributeMapper.class)) {

            // Mock IdentitySCIMManager and UserManager.
            IdentitySCIMManager mockSCIMManager = Mockito.mock(IdentitySCIMManager.class);
            UserManager mockUserManager = Mockito.mock(UserManager.class);
            identitySCIMManagerMock.when(IdentitySCIMManager::getInstance).thenReturn(mockSCIMManager);
            Mockito.when(mockSCIMManager.getUserManager()).thenReturn(mockUserManager);

            // Mock AttributeMapper to return a User object.
            User mockUser = new User();
            mockUser.setUserName("testUser");
            attributeMapperMock.when(() -> AttributeMapper.constructSCIMObjectFromAttributes(
                    Mockito.any(UserManager.class), Mockito.anyMap(), Mockito.anyInt()))
                    .thenReturn(mockUser);

            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");

            // Configure with PATCH disabled for updates (default behavior) via identity.xml.
            identityUtilMock.when(() -> IdentityUtil.getProperty(
                    IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES)).thenReturn("false");

            sCIM2ProvisioningConnector.init(new Property[0]);

            // Inject mocked scimProvider using reflection.
            java.lang.reflect.Field scimProviderField = SCIM2ProvisioningConnector.class.getDeclaredField("scimProvider");
            scimProviderField.setAccessible(true);
            scimProviderField.set(sCIM2ProvisioningConnector, scimProvider);

            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
            value.add("testUser");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI,
                    IdentityProvisioningConstants.USERNAME_CLAIM_URI, null, false), value);
            List<String> displayNameValue = new ArrayList<>();
            displayNameValue.add("Test User");
            String displayNameUri = "urn:ietf:params:scim:schemas:core:2.0:User:displayName";
            attributes.put(ClaimMapping.build(displayNameUri, displayNameUri, null, false), displayNameValue);

            ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER,
                    ProvisioningOperation.PUT, attributes);

            // Use reflection to call updateUser with PUT operation.
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateUser",
                    ProvisioningEntity.class, ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity, ProvisioningOperation.PUT);

            // Verify that provisionUpdateUser was called (because PATCH is disabled).
            assertEquals(mocked.constructed().size(), 1, "ProvisioningClient should be constructed once");
            ProvisioningClient client = mocked.constructed().get(0);
            Mockito.verify(client, Mockito.times(1)).provisionUpdateUser();
            Mockito.verify(client, Mockito.never()).provisionPatchUser();
        }
    }

    @Test
    public void testPatchOperationAlwaysUsesPatch() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class,
                (mock, context) -> {
                    // Verify that provisionPatchUser is called.
                });
             MockedStatic<IdentityUtil> identityUtilMock = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentitySCIMManager> identitySCIMManagerMock = Mockito.mockStatic(IdentitySCIMManager.class);
             MockedStatic<AttributeMapper> attributeMapperMock = Mockito.mockStatic(AttributeMapper.class)) {

            // Mock IdentitySCIMManager and UserManager.
            IdentitySCIMManager mockSCIMManager = Mockito.mock(IdentitySCIMManager.class);
            UserManager mockUserManager = Mockito.mock(UserManager.class);
            identitySCIMManagerMock.when(IdentitySCIMManager::getInstance).thenReturn(mockSCIMManager);
            Mockito.when(mockSCIMManager.getUserManager()).thenReturn(mockUserManager);

            // Mock AttributeMapper to return a User object.
            User mockUser = new User();
            mockUser.setUserName("testUser");
            attributeMapperMock.when(() -> AttributeMapper.constructSCIMObjectFromAttributes(
                    Mockito.any(UserManager.class), Mockito.anyMap(), Mockito.anyInt()))
                    .thenReturn(mockUser);

            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");

            // Configure with PATCH disabled - but PATCH operation should still use PATCH.
            identityUtilMock.when(() -> IdentityUtil.getProperty(
                    IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES)).thenReturn("false");

            sCIM2ProvisioningConnector.init(new Property[0]);

            // Inject mocked scimProvider using reflection.
            java.lang.reflect.Field scimProviderField = SCIM2ProvisioningConnector.class.getDeclaredField("scimProvider");
            scimProviderField.setAccessible(true);
            scimProviderField.set(sCIM2ProvisioningConnector, scimProvider);

            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
            value.add("testUser");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI,
                    IdentityProvisioningConstants.USERNAME_CLAIM_URI, null, false), value);
            List<String> displayNameValue = new ArrayList<>();
            displayNameValue.add("Test User");
            String displayNameUri = "urn:ietf:params:scim:schemas:core:2.0:User:displayName";
            attributes.put(ClaimMapping.build(displayNameUri, displayNameUri, null, false), displayNameValue);

            ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER,
                    ProvisioningOperation.PATCH, attributes);

            // Use reflection to call updateUser with PATCH operation.
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateUser",
                    ProvisioningEntity.class, ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity, ProvisioningOperation.PATCH);

            // Verify that provisionPatchUser was called (PATCH operation always uses PATCH).
            assertEquals(mocked.constructed().size(), 1, "ProvisioningClient should be constructed once");
            ProvisioningClient client = mocked.constructed().get(0);
            Mockito.verify(client, Mockito.times(1)).provisionPatchUser();
            Mockito.verify(client, Mockito.never()).provisionUpdateUser();
        }
    }

    @Test
    public void testPatchGroupWithMemberUpdates() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class,
                (mock, context) -> {
                    // Capture the additionalInformation passed to ProvisioningClient constructor.
                    Map<String, Object> additionalInfo = (Map<String, Object>) context.arguments().get(2);
                    if (additionalInfo != null) {
                        // Verify that NEW_MEMBERS and DELETED_MEMBERS are present in additionalInformation.
                        assertTrue(additionalInfo.containsKey(org.wso2.scim2.util.SCIM2CommonConstants.NEW_MEMBERS),
                                "additionalInformation should contain NEW_MEMBERS");
                        assertTrue(additionalInfo.containsKey(org.wso2.scim2.util.SCIM2CommonConstants.DELETED_MEMBERS),
                                "additionalInformation should contain DELETED_MEMBERS");

                        // Verify the values of NEW_MEMBERS and DELETED_MEMBERS.
                        List<String> newMembers = (List<String>) additionalInfo.get(
                                org.wso2.scim2.util.SCIM2CommonConstants.NEW_MEMBERS);
                        List<String> deletedMembers = (List<String>) additionalInfo.get(
                                org.wso2.scim2.util.SCIM2CommonConstants.DELETED_MEMBERS);

                        assertNotNull(newMembers, "NEW_MEMBERS should not be null");
                        assertNotNull(deletedMembers, "DELETED_MEMBERS should not be null");
                        assertEquals(newMembers.size(), 2, "Should have 2 new members");
                        assertEquals(deletedMembers.size(), 1, "Should have 1 deleted member");
                        assertTrue(newMembers.contains("newUser1"), "Should contain newUser1");
                        assertTrue(newMembers.contains("newUser2"), "Should contain newUser2");
                        assertTrue(deletedMembers.contains("removedUser"), "Should contain removedUser");
                    }
                })) {

            sCIM2ProvisioningConnector.init(new Property[0]);

            // Create attributes with group name, new users, and deleted users.
            Map<ClaimMapping, List<String>> attributes = new HashMap<>();

            // Set group name.
            List<String> groupName = new ArrayList<>();
            groupName.add("testGroup");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.NEW_GROUP_NAME_CLAIM_URI,
                    null, null, false), groupName);

            // Set new users to be added to the group.
            List<String> newUsers = new ArrayList<>();
            newUsers.add("newUser1");
            newUsers.add("newUser2");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.NEW_USER_CLAIM_URI,
                    null, null, false), newUsers);

            // Set users to be removed from the group.
            List<String> deletedUsers = new ArrayList<>();
            deletedUsers.add("removedUser");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.DELETED_USER_CLAIM_URI,
                    null, null, false), deletedUsers);

            // Create provisioning entity with PATCH operation.
            ProvisioningEntity groupEntity = new ProvisioningEntity(ProvisioningEntityType.GROUP,
                    ProvisioningOperation.PATCH, attributes);

            // Use reflection to call updateGroup with PATCH operation.
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateGroup",
                    ProvisioningEntity.class, ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, groupEntity, ProvisioningOperation.PATCH);

            // Verify that provisionPatchGroup was called.
            assertEquals(mocked.constructed().size(), 1,
                    "ProvisioningClient should be constructed once");
            ProvisioningClient client = mocked.constructed().get(0);
            Mockito.verify(client, Mockito.times(1)).provisionPatchGroup();
        }
    }
}
