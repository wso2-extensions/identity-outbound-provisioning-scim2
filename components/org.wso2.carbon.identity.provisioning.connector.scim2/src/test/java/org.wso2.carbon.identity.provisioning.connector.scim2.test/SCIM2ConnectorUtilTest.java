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

import org.json.JSONArray;
import org.json.JSONObject;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySetting;
import org.wso2.carbon.identity.compatibility.settings.core.model.CompatibilitySettingGroup;
import org.wso2.carbon.identity.compatibility.settings.core.service.CompatibilitySettingsService;
import org.wso2.carbon.identity.provisioning.connector.scim2.internal.SCIM2ConnectorServiceDataHolder;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorConstants;
import org.wso2.carbon.identity.provisioning.connector.scim2.util.SCIM2ConnectorUtil;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.carbon.identity.scim2.common.utils.AttributeMapper;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.ComplexAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMResourceTypeSchema;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit tests for SCIM2ConnectorUtil class.
 */
public class SCIM2ConnectorUtilTest {

    private static final String ENTERPRISE_SCHEMA_URI =
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    private static final String WSO2_SYSTEM_SCHEMA_URI = "urn:scim:wso2:schema";

    private MockedStatic<IdentityUtil> identityUtilMock;
    private MockedStatic<SCIMCommonUtils> scimCommonUtilsMock;
    private MockedStatic<IdentitySCIMManager> identitySCIMManagerMock;
    private MockedStatic<AttributeMapper> attributeMapperMock;
    private MockedStatic<SCIMResourceSchemaManager> resourceSchemaManagerMock;
    private SCIMResourceSchemaManager schemaManager;

    @BeforeMethod
    public void setUp() throws Exception {
        identityUtilMock = Mockito.mockStatic(IdentityUtil.class);
        scimCommonUtilsMock = Mockito.mockStatic(SCIMCommonUtils.class);
        identitySCIMManagerMock = Mockito.mockStatic(IdentitySCIMManager.class);
        attributeMapperMock = Mockito.mockStatic(AttributeMapper.class);
        resourceSchemaManagerMock = Mockito.mockStatic(SCIMResourceSchemaManager.class);
        setLegacyScim2Payload(false);

        // Every construction path resolves the tenant resource type schema; default it to core only and
        // let the tests that care about extensions override it.
        schemaManager = Mockito.mock(SCIMResourceSchemaManager.class);
        resourceSchemaManagerMock.when(SCIMResourceSchemaManager::getInstance).thenReturn(schemaManager);
        Mockito.when(schemaManager.getUserResourceSchema(any(UserManager.class))).thenReturn(
                SCIMResourceTypeSchema.createSCIMResourceSchema(
                        Collections.singletonList(SCIMConstants.USER_CORE_SCHEMA_URI)));
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
        if (resourceSchemaManagerMock != null) {
            resourceSchemaManagerMock.close();
        }
        SCIM2ConnectorServiceDataHolder.getInstance().setCompatibilitySettingsService(null);
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
    public void testBuildPatchOperationsFromUserWithComplexAttribute() throws CharonException {

        // Create a User with a non-multi-valued complex attribute (e.g., name).
        User user = Mockito.mock(User.class);
        Map<String, Attribute> attributeList = new HashMap<>();

        // Create a complex "name" attribute with sub-attributes familyName and givenName.
        ComplexAttribute nameAttr = Mockito.mock(ComplexAttribute.class);
        Mockito.when(nameAttr.getName()).thenReturn(SCIMConstants.UserSchemaConstants.NAME);
        Mockito.when(nameAttr.getMultiValued()).thenReturn(false);

        Map<String, Attribute> subAttributes = new HashMap<>();

        SimpleAttribute familyNameAttr = Mockito.mock(SimpleAttribute.class);
        Mockito.when(familyNameAttr.getName()).thenReturn(SCIMConstants.UserSchemaConstants.FAMILY_NAME);
        Mockito.when(familyNameAttr.getValue()).thenReturn("Smith");
        subAttributes.put(SCIMConstants.UserSchemaConstants.FAMILY_NAME, familyNameAttr);

        SimpleAttribute givenNameAttr = Mockito.mock(SimpleAttribute.class);
        Mockito.when(givenNameAttr.getName()).thenReturn(SCIMConstants.UserSchemaConstants.GIVEN_NAME);
        Mockito.when(givenNameAttr.getValue()).thenReturn("John");
        subAttributes.put(SCIMConstants.UserSchemaConstants.GIVEN_NAME, givenNameAttr);

        Mockito.when(nameAttr.getSubAttributesList()).thenReturn(subAttributes);
        attributeList.put(SCIMConstants.UserSchemaConstants.NAME, nameAttr);

        Mockito.when(user.getAttributeList()).thenReturn(attributeList);

        // Build patch operations.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify sub-attribute level patch operations are created.
        assertNotNull(patchOperations, "Patch operations should not be null");
        assertEquals(patchOperations.size(), 2, "Should have 2 patch operations for name sub-attributes");

        // Verify each operation uses dotted sub-attribute paths.
        Map<String, Object> pathValueMap = new HashMap<>();
        for (PatchOperation op : patchOperations) {
            assertEquals(op.getOperation(), SCIMConstants.OperationalConstants.REPLACE,
                    "Operation should be REPLACE");
            pathValueMap.put(op.getPath(), op.getValues());
        }

        assertTrue(pathValueMap.containsKey("name.familyName"),
                "Should have patch operation for name.familyName");
        assertEquals(pathValueMap.get("name.familyName"), "Smith",
                "name.familyName value should be Smith");

        assertTrue(pathValueMap.containsKey("name.givenName"),
                "Should have patch operation for name.givenName");
        assertEquals(pathValueMap.get("name.givenName"), "John",
                "name.givenName value should be John");
    }

    @Test
    public void testBuildPatchOperationsFromUserWithExtensionComplexSubAttribute() throws CharonException {

        // Create a User with an extension schema attribute containing a complex sub-attribute (e.g., manager).
        User user = Mockito.mock(User.class);
        Map<String, Attribute> attributeList = new HashMap<>();

        String enterpriseSchemaUri = SCIM2ProvisioningConnectorConstants.DEFAULT_SCIM2_ENTERPRISE_DIALECT;
        scimCommonUtilsMock.when(SCIMCommonUtils::getCustomSchemaURI).thenReturn(null);

        // Create the extension schema top-level complex attribute.
        ComplexAttribute extensionAttr = Mockito.mock(ComplexAttribute.class);
        Mockito.when(extensionAttr.getName()).thenReturn(enterpriseSchemaUri);
        Mockito.when(extensionAttr.getMultiValued()).thenReturn(false);

        Map<String, Attribute> extensionSubAttributes = new HashMap<>();

        // Add a simple sub-attribute (department).
        SimpleAttribute departmentAttr = Mockito.mock(SimpleAttribute.class);
        Mockito.when(departmentAttr.getName()).thenReturn("department");
        Mockito.when(departmentAttr.getValue()).thenReturn("Engineering");
        Mockito.when(departmentAttr.getMultiValued()).thenReturn(false);
        extensionSubAttributes.put("department", departmentAttr);

        // Add a complex non-multi-valued sub-attribute (manager) with sub-sub-attributes.
        ComplexAttribute managerAttr = Mockito.mock(ComplexAttribute.class);
        Mockito.when(managerAttr.getName()).thenReturn("manager");
        Mockito.when(managerAttr.getMultiValued()).thenReturn(false);

        Map<String, Attribute> managerSubAttributes = new HashMap<>();
        SimpleAttribute managerDisplayName = Mockito.mock(SimpleAttribute.class);
        Mockito.when(managerDisplayName.getName()).thenReturn("displayName");
        Mockito.when(managerDisplayName.getValue()).thenReturn("Jane Manager");
        managerSubAttributes.put("displayName", managerDisplayName);

        SimpleAttribute managerValue = Mockito.mock(SimpleAttribute.class);
        Mockito.when(managerValue.getName()).thenReturn("value");
        Mockito.when(managerValue.getValue()).thenReturn("user123");
        managerSubAttributes.put("value", managerValue);

        Mockito.when(managerAttr.getSubAttributesList()).thenReturn(managerSubAttributes);
        extensionSubAttributes.put("manager", managerAttr);

        Mockito.when(extensionAttr.getSubAttributesList()).thenReturn(extensionSubAttributes);
        attributeList.put(enterpriseSchemaUri, extensionAttr);

        Mockito.when(user.getAttributeList()).thenReturn(attributeList);

        // Build patch operations.
        List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

        // Verify patch operations.
        assertNotNull(patchOperations, "Patch operations should not be null");
        assertEquals(patchOperations.size(), 3,
                "Should have 3 patch operations: department + manager.displayName + manager.value");

        Map<String, Object> pathValueMap = new HashMap<>();
        for (PatchOperation op : patchOperations) {
            assertEquals(op.getOperation(), SCIMConstants.OperationalConstants.REPLACE,
                    "Operation should be REPLACE");
            pathValueMap.put(op.getPath(), op.getValues());
        }

        // Verify simple extension sub-attribute.
        String departmentPath = enterpriseSchemaUri + ":department";
        assertTrue(pathValueMap.containsKey(departmentPath),
                "Should have patch operation for department");
        assertEquals(pathValueMap.get(departmentPath), "Engineering",
                "department value should be Engineering");

        // Verify complex extension sub-attribute is split into sub-sub-attribute paths.
        String managerDisplayNamePath = enterpriseSchemaUri + ":manager.displayName";
        assertTrue(pathValueMap.containsKey(managerDisplayNamePath),
                "Should have patch operation for manager.displayName");
        assertEquals(pathValueMap.get(managerDisplayNamePath), "Jane Manager",
                "manager.displayName value should be Jane Manager");

        String managerValuePath = enterpriseSchemaUri + ":manager.value";
        assertTrue(pathValueMap.containsKey(managerValuePath),
                "Should have patch operation for manager.value");
        assertEquals(pathValueMap.get(managerValuePath), "user123",
                "manager.value value should be user123");
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

    @Test
    public void testConstructUserFromAttributesDeclaresOnlyTheSchemasInUse() throws Exception {

        // The tenant resource type schema offers two extensions; the payload uses only the enterprise one.
        User user = new User();
        user.getAttributeList().put(ENTERPRISE_SCHEMA_URI, new ComplexAttribute(ENTERPRISE_SCHEMA_URI));
        User result = constructUser(user, SCIMConstants.USER_CORE_SCHEMA_URI, ENTERPRISE_SCHEMA_URI,
                WSO2_SYSTEM_SCHEMA_URI);

        assertEquals(result.getSchemaList(), Arrays.asList(SCIMConstants.USER_CORE_SCHEMA_URI,
                        ENTERPRISE_SCHEMA_URI),
                "Only the core schema and the extensions present in the payload should be declared");
        assertFalse(result.getSchemaList().contains(WSO2_SYSTEM_SCHEMA_URI),
                "An extension the payload carries no attribute from should not be declared, because a strict " +
                        "target rejects a schema URI it does not recognise");
    }

    @Test
    public void testConstructUserFromAttributesDeclaresCoreSchemaWithNoExtensions() throws Exception {

        User result = constructUser(new User(), SCIMConstants.USER_CORE_SCHEMA_URI, ENTERPRISE_SCHEMA_URI);

        // The encoded payload is what goes on the wire; an empty schemas array is rejected by SCIM targets.
        JSONArray schemas = new JSONObject(new JSONEncoder().encodeSCIMObject(result))
                .getJSONArray(SCIMConstants.CommonSchemaConstants.SCHEMAS);
        assertEquals(schemas.length(), 1, "Encoded user payload should declare exactly the core user schema");
        assertEquals(schemas.getString(0), SCIMConstants.USER_CORE_SCHEMA_URI,
                "Encoded user payload should carry the SCIM core user schema URI");
    }

    @Test
    public void testConstructUserFromAttributesStripsMeta() throws Exception {

        // meta is read-only and describes this server's copy of the resource, so it must not be provisioned.
        User user = new User();
        user.getAttributeList().put(SCIMConstants.CommonSchemaConstants.META,
                new ComplexAttribute(SCIMConstants.CommonSchemaConstants.META));
        User result = constructUser(user, SCIMConstants.USER_CORE_SCHEMA_URI);

        assertNull(result.getAttribute(SCIMConstants.CommonSchemaConstants.META),
                "meta should be removed from the outbound payload");
        assertFalse(new JSONObject(new JSONEncoder().encodeSCIMObject(result))
                        .has(SCIMConstants.CommonSchemaConstants.META),
                "Encoded user payload should not carry meta");
    }

    /**
     * Runs constructUserFromAttributes over the given user, with a tenant resource type schema
     * offering the given schema URIs.
     */
    private User constructUser(User user, String... resourceTypeSchemaUris) throws Exception {

        Map<String, String> attributes = new HashMap<>();
        attributes.put(SCIMConstants.UserSchemaConstants.USER_NAME, "john.doe");

        IdentitySCIMManager scimManager = Mockito.mock(IdentitySCIMManager.class);
        UserManager userManager = Mockito.mock(UserManager.class);

        identitySCIMManagerMock.when(IdentitySCIMManager::getInstance).thenReturn(scimManager);
        Mockito.when(scimManager.getUserManager()).thenReturn(userManager);
        Mockito.when(schemaManager.getUserResourceSchema(any(UserManager.class))).thenReturn(
                SCIMResourceTypeSchema.createSCIMResourceSchema(Arrays.asList(resourceTypeSchemaUris)));
        attributeMapperMock.when(() -> AttributeMapper.constructSCIMObjectFromAttributes(
                any(UserManager.class), any(Map.class), Mockito.anyInt())).thenReturn(user);

        return SCIM2ConnectorUtil.constructUserFromAttributes(attributes);
    }

    @Test
    public void testLegacyPayloadIsLeftUntouched() throws Exception {

        setLegacyScim2Payload(true);

        User user = new User();
        user.getAttributeList().put(SCIMConstants.CommonSchemaConstants.META,
                new ComplexAttribute(SCIMConstants.CommonSchemaConstants.META));
        User result = constructUser(user, SCIMConstants.USER_CORE_SCHEMA_URI);

        assertTrue(result.getSchemaList().isEmpty(),
                "A tenant pinned to the legacy payload should keep the empty schemas array");
        assertNotNull(result.getAttribute(SCIMConstants.CommonSchemaConstants.META),
                "A tenant pinned to the legacy payload should keep meta");
    }

    @Test
    public void testPayloadFallsBackToLegacyWithoutTheCompatibilityService() throws Exception {

        // The service is unavailable, so the tenant must not be silently moved onto the new behaviour.
        setLegacyScim2Payload(null);

        User result = constructUser(new User(), SCIMConstants.USER_CORE_SCHEMA_URI);

        assertTrue(result.getSchemaList().isEmpty(),
                "An unavailable compatibility settings service should fail safe to the legacy payload");
    }

    /**
     * Pins the tenant to the legacy or the corrected outbound payload, the way the compatibility
     * setting does at runtime. Passing null leaves the service absent, which must fail safe to legacy.
     */
    static void setLegacyScim2Payload(Boolean legacy) {

        if (legacy == null) {
            SCIM2ConnectorServiceDataHolder.getInstance().setCompatibilitySettingsService(null);
            return;
        }
        System.setProperty("carbon.home", System.getProperty("user.dir"));

        CompatibilitySettingGroup group = new CompatibilitySettingGroup();
        group.setSettingGroup(SCIM2ProvisioningConnectorConstants.OUTBOUND_PROVISIONING_COMPATIBILITY_SETTING_GROUP);
        group.addSetting(SCIM2ProvisioningConnectorConstants.ENABLE_LEGACY_SCIM2_PAYLOAD, String.valueOf(legacy));
        CompatibilitySetting setting = new CompatibilitySetting();
        setting.addCompatibilitySetting(group);

        CompatibilitySettingsService service = Mockito.mock(CompatibilitySettingsService.class);
        try {
            Mockito.when(service.getCompatibilitySettingsByGroupAndSetting(
                    Mockito.nullable(String.class), Mockito.anyString(), Mockito.anyString())).thenReturn(setting);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        SCIM2ConnectorServiceDataHolder.getInstance().setCompatibilitySettingsService(service);
    }
}
