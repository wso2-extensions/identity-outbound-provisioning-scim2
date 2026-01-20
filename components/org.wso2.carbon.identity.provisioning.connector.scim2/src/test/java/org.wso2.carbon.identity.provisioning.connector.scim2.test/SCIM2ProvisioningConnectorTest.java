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
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.attributes.SimpleAttribute;
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
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateGroup", ProvisioningEntity.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, groupEntity);
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
    public void testBuildPatchOperationsFromUser() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create a User object with some attributes.
        User testUser = new User();
        testUser.setUserName("testUser");

        // Call the public static method from SCIM2ConnectorUtil.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(testUser);

        // Verify patch operations are created.
        assertNotNull(patchOperations);
        assertTrue(patchOperations.size() > 0);

        // Verify that metadata attributes are not included.
        boolean hasIdAttribute = false;
        boolean hasMetaAttribute = false;
        boolean hasSchemasAttribute = false;

        for (PatchOperation op : patchOperations) {
            if (SCIMConstants.CommonSchemaConstants.ID.equals(op.getPath())) {
                hasIdAttribute = true;
            }
            if (SCIMConstants.CommonSchemaConstants.META.equals(op.getPath())) {
                hasMetaAttribute = true;
            }
            if (SCIMConstants.CommonSchemaConstants.SCHEMAS.equals(op.getPath())) {
                hasSchemasAttribute = true;
            }
        }

        // Metadata attributes should not be in patch operations.
        assertFalse(hasIdAttribute, "ID attribute should not be in patch operations");
        assertFalse(hasMetaAttribute, "Meta attribute should not be in patch operations");
        assertFalse(hasSchemasAttribute, "Schemas attribute should not be in patch operations");

        // Verify all patch operations have the REPLACE operation.
        for (PatchOperation op : patchOperations) {
            assertEquals(op.getOperation(), SCIMConstants.OperationalConstants.REPLACE);
            assertNotNull(op.getPath());
        }
    }

    @Test
    public void testGetAttributeValueForSimpleAttribute() throws Exception {

        // This test is now part of the SCIM2ConnectorUtil functionality.
        // Testing through the public buildPatchOperationsFromUser method.
        User testUser = new User();
        testUser.setUserName("testUser");

        SimpleAttribute displayName = new SimpleAttribute("displayName", "John Doe");
        testUser.setAttribute(displayName);

        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(testUser);

        // Verify the display name was extracted correctly.
        assertNotNull(patchOperations);
        boolean hasDisplayName = patchOperations.stream()
                .anyMatch(op -> "displayName".equals(op.getPath()) && "John Doe".equals(op.getValues()));
        assertTrue(hasDisplayName, "Display name should be in patch operations");
    }

    @Test
    public void testGetAttributeValueForComplexAttribute() throws Exception {

        // Test through the public buildPatchOperationsFromUser method.
        User testUser = new User();
        testUser.setUserName("testUser");

        // Create a complex attribute (name).
        org.wso2.charon3.core.attributes.ComplexAttribute complexAttribute =
                new org.wso2.charon3.core.attributes.ComplexAttribute("name");

        SimpleAttribute givenName = new SimpleAttribute("givenName", "John");
        SimpleAttribute familyName = new SimpleAttribute("familyName", "Doe");

        complexAttribute.setSubAttribute(givenName);
        complexAttribute.setSubAttribute(familyName);
        testUser.setAttribute(complexAttribute);

        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(testUser);

        // Verify the complex attribute was processed.
        assertNotNull(patchOperations);
        assertTrue(patchOperations.size() > 0, "Should have patch operations");

        // Find the name operation.
        Optional<PatchOperation> nameOp = patchOperations.stream()
                .filter(op -> "name".equals(op.getPath()))
                .findFirst();

        assertTrue(nameOp.isPresent(), "Should have name operation");
        assertNotNull(nameOp.get().getValues(), "Name value should not be null");
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
    public void testPatchOperationStructure() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create a User object with attributes.
        User patchUser = new User();
        patchUser.setUserName("testUser");

        // Call the public static method from SCIM2ConnectorUtil.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(patchUser);

        // Verify structure of each patch operation.
        for (PatchOperation op : patchOperations) {
            assertNotNull(op.getOperation(), "Operation type should not be null");
            assertNotNull(op.getPath(), "Path should not be null");
            assertEquals(op.getOperation(), SCIMConstants.OperationalConstants.REPLACE,
                    "All operations should be REPLACE");
        }
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
    public void testBuildPatchOperationsWithEnterpriseExtensionSimpleAttributes() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create a User with Enterprise extension simple attributes.
        User user = new User();
        user.setUserName("testUser");

        // Create Enterprise extension complex attribute.
        org.wso2.charon3.core.attributes.ComplexAttribute enterpriseExt =
                new org.wso2.charon3.core.attributes.ComplexAttribute(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");

        // Add simple attributes to enterprise extension.
        SimpleAttribute department = new SimpleAttribute("department", "Engineering");
        SimpleAttribute country = new SimpleAttribute("country", "UK");
        SimpleAttribute employeeNumber = new SimpleAttribute("employeeNumber", "EMP001");

        enterpriseExt.setSubAttribute(department);
        enterpriseExt.setSubAttribute(country);
        enterpriseExt.setSubAttribute(employeeNumber);

        // Set the enterprise extension on the user.
        user.setAttribute(enterpriseExt);

        // Call the public static method from SCIM2ConnectorUtil.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify patch operations are created.
        assertNotNull(patchOperations);
        assertTrue(patchOperations.size() > 0, "Patch operations should be generated");

        // Find enterprise extension operations.
        List<PatchOperation> enterpriseOps = patchOperations.stream()
                .filter(op -> op.getPath() != null && op.getPath().contains("enterprise"))
                .collect(Collectors.toList());

        assertTrue(enterpriseOps.size() >= 3, "Should have at least 3 enterprise extension operations");

        // Verify path format: schema:attributeName.
        boolean hasDepartmentOp = enterpriseOps.stream()
                .anyMatch(op -> op.getPath().equals(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department") &&
                        "Engineering".equals(op.getValues()));
        assertTrue(hasDepartmentOp, "Should have department operation with correct path format");

        boolean hasCountryOp = enterpriseOps.stream()
                .anyMatch(op -> op.getPath().equals(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:country") &&
                        "UK".equals(op.getValues()));
        assertTrue(hasCountryOp, "Should have country operation with correct path format");

        boolean hasEmployeeNumberOp = enterpriseOps.stream()
                .anyMatch(op -> op.getPath().equals(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber") &&
                        "EMP001".equals(op.getValues()));
        assertTrue(hasEmployeeNumberOp, "Should have employeeNumber operation with correct path format");

        // Verify all operations are REPLACE.
        for (PatchOperation op : enterpriseOps) {
            assertEquals(op.getOperation(), SCIMConstants.OperationalConstants.REPLACE,
                    "All operations should be REPLACE");
        }
    }

    @Test
    public void testBuildPatchOperationsWithEnterpriseExtensionComplexAttributes() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create a User with Enterprise extension complex attributes.
        User user = new User();
        user.setUserName("testUser");

        // Create Enterprise extension complex attribute.
        org.wso2.charon3.core.attributes.ComplexAttribute enterpriseExt =
                new org.wso2.charon3.core.attributes.ComplexAttribute(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");

        // Add complex manager attribute.
        org.wso2.charon3.core.attributes.ComplexAttribute manager =
                new org.wso2.charon3.core.attributes.ComplexAttribute("manager");
        SimpleAttribute managerDisplayName = new SimpleAttribute("displayName", "Manager Name");
        SimpleAttribute managerValueAttr = new SimpleAttribute("value", "manager-id-123");
        manager.setSubAttribute(managerDisplayName);
        manager.setSubAttribute(managerValueAttr);

        enterpriseExt.setSubAttribute(manager);

        // Set the enterprise extension on the user.
        user.setAttribute(enterpriseExt);

        // Call the public static method from SCIM2ConnectorUtil.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify patch operations are created.
        assertNotNull(patchOperations);
        assertTrue(patchOperations.size() > 0, "Patch operations should be generated");

        // Find manager operation.
        Optional<PatchOperation> managerOp = patchOperations.stream()
                .filter(op -> op.getPath() != null &&
                        op.getPath().equals("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager"))
                .findFirst();

        assertTrue(managerOp.isPresent(), "Should have manager operation");

        // Verify manager operation has complex value.
        Object managerValue = managerOp.get().getValues();
        assertNotNull(managerValue, "Manager value should not be null");
        assertTrue(managerValue instanceof JSONObject, "Manager value should be a JSONObject");

        JSONObject managerJson = (JSONObject) managerValue;
        assertTrue(managerJson.has("displayName"), "Manager should have displayName");
        assertTrue(managerJson.has("value"), "Manager should have value");
        assertEquals(managerJson.getString("displayName"), "Manager Name");
        assertEquals(managerJson.getString("value"), "manager-id-123");
    }

    @Test
    public void testBuildPatchOperationsWithMixedCoreAndExtensionAttributes() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create a User with both core and extension attributes.
        User user = new User();
        user.setUserName("testUser");

        // Add core attribute.
        SimpleAttribute displayName = new SimpleAttribute("displayName", "Test User");
        user.setAttribute(displayName);

        SimpleAttribute nickName = new SimpleAttribute("nickName", "TU");
        user.setAttribute(nickName);

        // Create Enterprise extension with simple attributes.
        org.wso2.charon3.core.attributes.ComplexAttribute enterpriseExt =
                new org.wso2.charon3.core.attributes.ComplexAttribute(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");

        SimpleAttribute department = new SimpleAttribute("department", "Engineering");
        SimpleAttribute country = new SimpleAttribute("country", "USA");
        enterpriseExt.setSubAttribute(department);
        enterpriseExt.setSubAttribute(country);

        user.setAttribute(enterpriseExt);

        // Call the public static method from SCIM2ConnectorUtil.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify patch operations are created.
        assertNotNull(patchOperations);
        assertTrue(patchOperations.size() >= 4, "Should have at least 4 operations (2 core + 2 extension)");

        // Verify core attribute operations (simple paths).
        boolean hasDisplayNameOp = patchOperations.stream()
                .anyMatch(op -> "displayName".equals(op.getPath()) && "Test User".equals(op.getValues()));
        assertTrue(hasDisplayNameOp, "Should have displayName operation");

        boolean hasNickNameOp = patchOperations.stream()
                .anyMatch(op -> "nickName".equals(op.getPath()) && "TU".equals(op.getValues()));
        assertTrue(hasNickNameOp, "Should have nickName operation");

        // Verify extension attribute operations (full schema:attribute paths).
        boolean hasDepartmentOp = patchOperations.stream()
                .anyMatch(op -> "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department".equals(op.getPath()) &&
                        "Engineering".equals(op.getValues()));
        assertTrue(hasDepartmentOp, "Should have department operation with full schema path");

        boolean hasCountryOp = patchOperations.stream()
                .anyMatch(op -> "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:country".equals(op.getPath()) &&
                        "USA".equals(op.getValues()));
        assertTrue(hasCountryOp, "Should have country operation with full schema path");
    }

    @Test
    public void testBuildPatchOperationsExcludesMetadataFromExtensions() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create a User with extension attributes.
        User user = new User();
        user.setUserName("testUser");

        // Create Enterprise extension.
        org.wso2.charon3.core.attributes.ComplexAttribute enterpriseExt =
                new org.wso2.charon3.core.attributes.ComplexAttribute(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");

        SimpleAttribute department = new SimpleAttribute("department", "Engineering");
        enterpriseExt.setSubAttribute(department);
        user.setAttribute(enterpriseExt);

        // Call the public static method from SCIM2ConnectorUtil.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify no metadata attributes are included.
        boolean hasIdAttribute = patchOperations.stream()
                .anyMatch(op -> SCIMConstants.CommonSchemaConstants.ID.equals(op.getPath()));
        assertFalse(hasIdAttribute, "ID attribute should not be in patch operations");

        boolean hasMetaAttribute = patchOperations.stream()
                .anyMatch(op -> SCIMConstants.CommonSchemaConstants.META.equals(op.getPath()));
        assertFalse(hasMetaAttribute, "Meta attribute should not be in patch operations");

        boolean hasSchemasAttribute = patchOperations.stream()
                .anyMatch(op -> SCIMConstants.CommonSchemaConstants.SCHEMAS.equals(op.getPath()));
        assertFalse(hasSchemasAttribute, "Schemas attribute should not be in patch operations");

        boolean hasPasswordAttribute = patchOperations.stream()
                .anyMatch(op -> SCIMConstants.UserSchemaConstants.PASSWORD.equals(op.getPath()));
        assertFalse(hasPasswordAttribute, "Password attribute should not be in patch operations");
    }

    @Test
    public void testBuildPatchOperationsVerifiesPathFormat() throws Exception {

        sCIM2ProvisioningConnector.init(new Property[0]);

        // Create a User with Enterprise extension.
        User user = new User();
        user.setUserName("testUser");

        org.wso2.charon3.core.attributes.ComplexAttribute enterpriseExt =
                new org.wso2.charon3.core.attributes.ComplexAttribute(
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User");

        SimpleAttribute department = new SimpleAttribute("department", "Sales");
        enterpriseExt.setSubAttribute(department);
        user.setAttribute(enterpriseExt);

        // Call the public static method from SCIM2ConnectorUtil.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Find the department operation.
        Optional<PatchOperation> deptOp = patchOperations.stream()
                .filter(op -> op.getPath() != null && op.getPath().contains("department"))
                .findFirst();

        assertTrue(deptOp.isPresent(), "Department operation should exist");

        // Verify path format matches WSO2 documentation pattern: schema:attributeName.
        String expectedPath = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department";
        assertEquals(deptOp.get().getPath(), expectedPath,
                "Path should follow schema:attributeName format as per WSO2 documentation");

        // Verify value is the simple attribute value, not a complex object.
        assertEquals(deptOp.get().getValues(), "Sales",
                "Value should be the simple attribute value");

        // Verify it's NOT the incorrect format (entire extension as value).
        assertFalse(deptOp.get().getPath().equals("urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"),
                "Path should not be just the schema URI");
    }

    @Test
    public void testUpdateUserWithPatchEnabledConfig() throws Exception {

        try (MockedConstruction<ProvisioningClient> mocked = Mockito.mockConstruction(ProvisioningClient.class,
                (mock, context) -> {
                    // Verify that provisionPatchUser is called (not provisionUpdateUser).
                });
             MockedStatic<IdentityUtil> identityUtilMock = Mockito.mockStatic(IdentityUtil.class)) {

            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");

            // Configure with PATCH enabled for updates via identity.xml.
            identityUtilMock.when(() -> IdentityUtil.getProperty(
                    IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES)).thenReturn("true");

            sCIM2ProvisioningConnector.init(new Property[0]);

            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
            value.add("testUser");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI, null, null,
                    false), value);
            List<String> displayNameValue = new ArrayList<>();
            displayNameValue.add("Test User");
            attributes.put(ClaimMapping.build("urn:ietf:params:scim:schemas:core:2.0:User:displayName", null, null,
                    false), displayNameValue);

            ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER,
                    ProvisioningOperation.PUT, attributes);

            // Use reflection to call updateUser with PUT operation.
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateUser",
                    ProvisioningEntity.class, ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity, ProvisioningOperation.PUT);

            // Verify that provisionPatchUser was called (because PATCH is enabled).
            assertEquals(1, mocked.constructed().size(), "ProvisioningClient should be constructed once");
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
             MockedStatic<IdentityUtil> identityUtilMock = Mockito.mockStatic(IdentityUtil.class)) {

            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");

            // Configure with PATCH disabled for updates (default behavior) via identity.xml.
            identityUtilMock.when(() -> IdentityUtil.getProperty(
                    IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES)).thenReturn("false");

            sCIM2ProvisioningConnector.init(new Property[0]);

            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
            value.add("testUser");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI, null, null,
                    false), value);
            List<String> displayNameValue = new ArrayList<>();
            displayNameValue.add("Test User");
            attributes.put(ClaimMapping.build("urn:ietf:params:scim:schemas:core:2.0:User:displayName", null, null,
                    false), displayNameValue);

            ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER,
                    ProvisioningOperation.PUT, attributes);

            // Use reflection to call updateUser with PUT operation.
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateUser",
                    ProvisioningEntity.class, ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity, ProvisioningOperation.PUT);

            // Verify that provisionUpdateUser was called (because PATCH is disabled).
            assertEquals(1, mocked.constructed().size(), "ProvisioningClient should be constructed once");
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
             MockedStatic<IdentityUtil> identityUtilMock = Mockito.mockStatic(IdentityUtil.class)) {

            Mockito.when(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                    SCIM2_ENABLE_PASSWORD_PROVISIONING)).thenReturn("true");

            // Configure with PATCH disabled - but PATCH operation should still use PATCH.
            identityUtilMock.when(() -> IdentityUtil.getProperty(
                    IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES)).thenReturn("false");

            sCIM2ProvisioningConnector.init(new Property[0]);

            Map<ClaimMapping, List<String>> attributes = new HashMap<>();
            List<String> value = new ArrayList<>();
            value.add("testUser");
            attributes.put(ClaimMapping.build(IdentityProvisioningConstants.USERNAME_CLAIM_URI, null, null,
                    false), value);
            List<String> displayNameValue = new ArrayList<>();
            displayNameValue.add("Test User");
            attributes.put(ClaimMapping.build("urn:ietf:params:scim:schemas:core:2.0:User:displayName", null, null,
                    false), displayNameValue);

            ProvisioningEntity userEntity = new ProvisioningEntity(ProvisioningEntityType.USER,
                    ProvisioningOperation.PATCH, attributes);

            // Use reflection to call updateUser with PATCH operation.
            Method method = SCIM2ProvisioningConnector.class.getDeclaredMethod("updateUser",
                    ProvisioningEntity.class, ProvisioningOperation.class);
            method.setAccessible(true);
            method.invoke(sCIM2ProvisioningConnector, userEntity, ProvisioningOperation.PATCH);

            // Verify that provisionPatchUser was called (PATCH operation always uses PATCH).
            assertEquals(1, mocked.constructed().size(), "ProvisioningClient should be constructed once");
            ProvisioningClient client = mocked.constructed().get(0);
            Mockito.verify(client, Mockito.times(1)).provisionPatchUser();
            Mockito.verify(client, Mockito.never()).provisionUpdateUser();
        }
    }
}
