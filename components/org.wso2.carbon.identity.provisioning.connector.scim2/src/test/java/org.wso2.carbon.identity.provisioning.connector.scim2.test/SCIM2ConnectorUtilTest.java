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

package org.wso2.carbon.identity.provisioning.connector.scim2.test;

import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorConstants;
import org.wso2.carbon.identity.provisioning.connector.scim2.util.SCIM2ConnectorUtil;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for SCIM2ConnectorUtil class.
 */
public class SCIM2ConnectorUtilTest {

    private MockedStatic<IdentityUtil> identityUtilMock;
    private MockedStatic<SCIMCommonUtils> scimCommonUtilsMock;
    private MockedStatic<IdentitySCIMManager> identitySCIMManagerMock;
    private MockedStatic<AttributeMapper> attributeMapperMock;

    @BeforeMethod
    public void setUp() {
        identityUtilMock = Mockito.mockStatic(IdentityUtil.class);
        scimCommonUtilsMock = Mockito.mockStatic(SCIMCommonUtils.class);
        identitySCIMManagerMock = Mockito.mockStatic(IdentitySCIMManager.class);
        attributeMapperMock = Mockito.mockStatic(AttributeMapper.class);
    }

    @AfterMethod
    public void tearDown() {
        if (identityUtilMock != null) {
            identityUtilMock.close();
        }
        if (scimCommonUtilsMock != null) {
            scimCommonUtilsMock.close();
        }
        if (identitySCIMManagerMock != null) {
            identitySCIMManagerMock.close();
        }
        if (attributeMapperMock != null) {
            attributeMapperMock.close();
        }
    }

    @Test
    public void testCreateDisplayNamePatchOperation() {

        // Test with a valid display name.
        String displayName = "Engineering Team";
        PatchOperation patchOp = SCIM2ConnectorUtil.createDisplayNamePatchOperation(displayName);

        // Verify the patch operation is not null.
        assertNotNull(patchOp, "PatchOperation should not be null");

        // Verify the operation type is REPLACE.
        assertEquals(patchOp.getOperation(), SCIMConstants.OperationalConstants.REPLACE,
                "Operation should be REPLACE");

        // Verify the path is set to displayName.
        assertEquals(patchOp.getPath(), SCIMConstants.GroupSchemaConstants.DISPLAY_NAME,
                "Path should be displayName");

        // Verify the value is set correctly.
        assertEquals(patchOp.getValues(), displayName, "Values should match the provided display name");
    }

    @Test
    public void testIsSCIMPatchEnabledForUpdates() {

        // Test when PATCH is enabled.
        identityUtilMock.when(() -> IdentityUtil.getProperty(
                IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES)).thenReturn("true");

        boolean result = SCIM2ConnectorUtil.isSCIMPatchEnabledForUpdates();
        assertTrue(result, "PATCH should be enabled when property is set to true");

        // Test when PATCH is disabled.
        identityUtilMock.when(() -> IdentityUtil.getProperty(
                IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES)).thenReturn("false");

        result = SCIM2ConnectorUtil.isSCIMPatchEnabledForUpdates();
        assertFalse(result, "PATCH should be disabled when property is set to false");
    }

    @Test
    public void testBuildPatchOperationsFromUserWithSimpleAttributes() throws CharonException {

        // Create a User with simple attributes.
        User user = Mockito.mock(User.class);
        Map<String, Attribute> attributeList = new HashMap<>();

        SimpleAttribute userNameAttr = Mockito.mock(SimpleAttribute.class);
        Mockito.when(userNameAttr.getName()).thenReturn(SCIMConstants.UserSchemaConstants.USER_NAME);
        Mockito.when(userNameAttr.getValue()).thenReturn("john.doe");
        attributeList.put(SCIMConstants.UserSchemaConstants.USER_NAME, userNameAttr);

        SimpleAttribute emailAttr = Mockito.mock(SimpleAttribute.class);
        Mockito.when(emailAttr.getName()).thenReturn(SCIMConstants.UserSchemaConstants.EMAILS);
        Mockito.when(emailAttr.getValue()).thenReturn("john.doe@example.com");
        attributeList.put(SCIMConstants.UserSchemaConstants.EMAILS, emailAttr);

        Mockito.when(user.getAttributeList()).thenReturn(attributeList);

        // Build patch operations.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify patch operations are created.
        assertNotNull(patchOperations, "Patch operations should not be null");
        assertEquals(patchOperations.size(), 2, "Should have 2 patch operations");

        // Verify operation details.
        for (PatchOperation op : patchOperations) {
            assertEquals(op.getOperation(), SCIMConstants.OperationalConstants.REPLACE,
                    "Operation should be REPLACE");
        }
    }

    @Test
    public void testBuildPatchOperationsFromUserWithNullUser() {

        // Test with null user.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(null);

        // Verify empty list is returned.
        assertNotNull(patchOperations, "Patch operations should not be null");
        assertTrue(patchOperations.isEmpty(), "Patch operations should be empty for null user");
    }

    @Test
    public void testBuildPatchOperationsFromUserWithEmptyAttributes() {

        // Create a User with empty attributes.
        User user = Mockito.mock(User.class);
        Mockito.when(user.getAttributeList()).thenReturn(new HashMap<>());

        // Build patch operations.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify empty list is returned.
        assertNotNull(patchOperations, "Patch operations should not be null");
        assertTrue(patchOperations.isEmpty(), "Patch operations should be empty for user with empty attributes");
    }

    @Test
    public void testIsExtensionSchemaWithEnterpriseSchema() {

        // Test with enterprise schema attribute.
        String enterpriseAttr = SCIM2ProvisioningConnectorConstants.DEFAULT_SCIM2_ENTERPRISE_DIALECT + ":employeeNumber";
        scimCommonUtilsMock.when(SCIMCommonUtils::getCustomSchemaURI).thenReturn("urn:custom:schema");

        boolean result = SCIM2ConnectorUtil.isExtensionSchema(enterpriseAttr);
        assertTrue(result, "Should recognize enterprise schema as extension");
    }

    @Test
    public void testIsExtensionSchemaWithCustomSchema() {

        // Test with custom schema attribute.
        String customSchemaUri = "urn:custom:schema";
        scimCommonUtilsMock.when(SCIMCommonUtils::getCustomSchemaURI).thenReturn(customSchemaUri);
        String customAttr = customSchemaUri + ":customAttribute";

        boolean result = SCIM2ConnectorUtil.isExtensionSchema(customAttr);
        assertTrue(result, "Should recognize custom schema as extension");
    }

    @Test
    public void testIsExtensionSchemaWithCoreAttribute() {

        // Test with core schema attribute.
        scimCommonUtilsMock.when(SCIMCommonUtils::getCustomSchemaURI).thenReturn("urn:custom:schema");
        String coreAttr = SCIMConstants.UserSchemaConstants.USER_NAME;

        boolean result = SCIM2ConnectorUtil.isExtensionSchema(coreAttr);
        assertFalse(result, "Should not recognize core attribute as extension");
    }

    @Test
    public void testIsExtensionSchemaWithNullAttribute() {

        // Test with null attribute.
        scimCommonUtilsMock.when(SCIMCommonUtils::getCustomSchemaURI).thenReturn("urn:custom:schema");

        boolean result = SCIM2ConnectorUtil.isExtensionSchema(null);
        assertFalse(result, "Should return false for null attribute");
    }

    @Test
    public void testIsExtensionSchemaWithEmptyAttribute() {

        // Test with empty attribute.
        scimCommonUtilsMock.when(SCIMCommonUtils::getCustomSchemaURI).thenReturn("urn:custom:schema");

        boolean result = SCIM2ConnectorUtil.isExtensionSchema("");
        assertFalse(result, "Should return false for empty attribute");
    }

    @Test
    public void testMaskIfRequiredWhenMaskingDisabled() {

        // Test when masking is disabled (default behavior).
        String value = "sensitiveValue";
        LoggerUtils.isLogMaskingEnable = false;

        String result = SCIM2ConnectorUtil.maskIfRequired(value);
        assertEquals(result, value, "Value should not be masked when masking is disabled");
    }

    @Test
    public void testConstructUserFromAttributes() throws Exception {

        // Test user construction from attributes.
        Map<String, String> attributes = new HashMap<>();
        attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME, "john.doe");
        attributes.put(SCIMConstants.UserSchemaConstants.GIVEN_NAME, "John");
        attributes.put(SCIMConstants.UserSchemaConstants.FAMILY_NAME, "Doe");

        // Mock dependencies.
        IdentitySCIMManager scimManager = Mockito.mock(IdentitySCIMManager.class);
        UserManager userManager = Mockito.mock(UserManager.class);
        User mockUser = Mockito.mock(User.class);

        identitySCIMManagerMock.when(IdentitySCIMManager::getInstance).thenReturn(scimManager);
        Mockito.when(scimManager.getUserManager()).thenReturn(userManager);
        attributeMapperMock.when(() -> AttributeMapper.constructSCIMObjectFromAttributes(
                any(UserManager.class), any(Map.class), Mockito.anyInt())).thenReturn(mockUser);

        // Construct user.
        User result = SCIM2ConnectorUtil.constructUserFromAttributes(attributes);

        // Verify user is constructed.
        assertNotNull(result, "User should not be null");
    }
}
