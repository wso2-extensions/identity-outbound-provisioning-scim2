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
import org.json.JSONObject;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorConstants;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.ComplexAttribute;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.encoder.JSONEncoder;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.utils.codeutils.PatchOperation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Utility class for SCIM2 provisioning connector configuration and helper methods.
 */
public class SCIM2ConnectorUtil {

    private static final Log log = LogFactory.getLog(SCIM2ConnectorUtil.class);

    private SCIM2ConnectorUtil() {
        // Private constructor to prevent instantiation.
    }

    /**
     * Checks whether SCIM PATCH should be used for user update operations.
     * This configuration is read from identity.xml under OutboundProvisioning section.
     *
     * @return true if PATCH should be used for updates, false otherwise.
     */
    public static boolean isSCIMPatchEnabledForUpdates() {

        return Boolean.parseBoolean(
                IdentityUtil.getProperty(IdentityProvisioningConstants.ENABLE_SCIM_PATCH_FOR_UPDATES));
    }

    /**
     * Builds PATCH operations from User object attributes.
     * This method converts SCIM User attributes to SCIM PATCH operations by traversing the User object's
     * attribute map and creating replace operations for each attribute.
     *
     * @param user User object with attributes to be patched.
     * @return List of PatchOperation objects.
     */
    public static List<PatchOperation> buildPatchOperationsFromUser(User user) {

        List<PatchOperation> patchOperations = new ArrayList<>();

        if (user == null || user.getAttributeList() == null || user.getAttributeList().isEmpty()) {
            return patchOperations;
        }

        try {
            // Iterate through User object's attributes and convert to patch operations.
            Map<String, Attribute> attributeList = user.getAttributeList();
            JSONEncoder encoder = new JSONEncoder();

            for (Map.Entry<String, Attribute> entry : attributeList.entrySet()) {
                String attributeName = entry.getKey();
                Attribute attribute = entry.getValue();

                // Check if this is an extension schema attribute.
                if (isExtensionSchema(attributeName) && attribute instanceof ComplexAttribute) {
                    // For extension schemas, create patch operations for each sub-attribute.
                    buildExtensionSchemaPatchOperations((ComplexAttribute) attribute, attributeName,
                            patchOperations, encoder);
                } else {
                    // For core attributes, create a single patch operation.
                    Object attributeValue = getAttributeValue(attribute, encoder);
                    if (attributeValue != null) {
                        createAndAddPatchOperation(attributeName, attributeValue, patchOperations);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error building patch operations from User object", e);
        }

        return patchOperations;
    }

    /**
     * Checks whether the given attribute name belongs to an extension schema.
     * An attribute is considered an extension if it starts with any known
     * extension dialect URI.
     *
     * @param attributeName Attribute name to validate.
     * @return true if the attribute belongs to an extension schema, false otherwise.
     */
    public static boolean isExtensionSchema(String attributeName) {

        if (StringUtils.isBlank(attributeName)) {
            return false;
        }

        // First check against registered extension dialect URIs.
        String[] extensionDialectUris = {
                SCIM2ProvisioningConnectorConstants.DEFAULT_SCIM2_ENTERPRISE_DIALECT,
                SCIM2ProvisioningConnectorConstants.DEFAULT_SCIM2_WSO2_DIALECT,
                SCIMCommonUtils.getCustomSchemaURI()
        };

        return Arrays.stream(extensionDialectUris)
                .filter(Objects::nonNull)
                .anyMatch(attributeName::startsWith);
    }

    /**
     * Builds PATCH operations for extension schema attributes.
     * Extension schemas (like enterprise user) need special handling where each sub-attribute
     * becomes a separate patch operation with the full path (schema:attributeName).
     *
     * @param complexAttribute The complex attribute representing the extension schema.
     * @param schemaUri        The schema URI (e.g., urn:ietf:params:scim:schemas:extension:enterprise:2.0:User).
     * @param patchOperations  List to add patch operations to.
     * @param encoder          JSONEncoder for encoding complex values.
     */
    private static void buildExtensionSchemaPatchOperations(ComplexAttribute complexAttribute, String schemaUri,
                                                            List<PatchOperation> patchOperations, JSONEncoder encoder) {

        try {
            Map<String, Attribute> subAttributes = complexAttribute.getSubAttributesList();

            if (subAttributes == null || subAttributes.isEmpty()) {
                return;
            }

            for (Map.Entry<String, Attribute> subAttrEntry : subAttributes.entrySet()) {
                String subAttrName = subAttrEntry.getKey();
                Attribute subAttribute = subAttrEntry.getValue();

                // Build the full path: schema:attributeName.
                String fullPath = schemaUri + ":" + subAttrName;

                // Extract attribute value and create patch operation.
                Object value = getAttributeValue(subAttribute, encoder);
                if (value != null) {
                    createAndAddPatchOperation(fullPath, value, patchOperations);
                }
            }
        } catch (Exception e) {
            log.error("Error building extension schema patch operations for schema: " + schemaUri, e);
        }
    }

    /**
     * Extracts the value from a SCIM attribute based on its type.
     *
     * @param attribute The SCIM attribute.
     * @param encoder   JSONEncoder for encoding complex attributes.
     * @return The attribute value.
     */
    private static Object getAttributeValue(Attribute attribute, JSONEncoder encoder) {

        try {
            if (attribute instanceof SimpleAttribute) {
                return ((SimpleAttribute) attribute).getValue();
            } else if (attribute instanceof ComplexAttribute) {
                // For complex attributes, encode as JSON object.
                JSONObject jsonObject = new JSONObject();
                encoder.encodeComplexAttribute((ComplexAttribute) attribute, jsonObject);
                return jsonObject.get(attribute.getName());
            } else if (attribute instanceof MultiValuedAttribute) {
                // For multi-valued attributes, encode as JSON array.
                JSONObject jsonObject = new JSONObject();
                encoder.encodeMultiValuedAttribute((MultiValuedAttribute) attribute, jsonObject);
                return jsonObject.get(attribute.getName());
            }
        } catch (Exception e) {
            log.error("Error extracting attribute value for attribute: " + attribute.getName(), e);
        }

        return null;
    }

    /**
     * Creates a PATCH operation and adds it to the provided list.
     *
     * @param path            The path for the patch operation.
     * @param value           The value for the patch operation.
     * @param patchOperations List to add the patch operation to.
     */
    private static void createAndAddPatchOperation(String path, Object value, List<PatchOperation> patchOperations) {

        PatchOperation patchOp = new PatchOperation();
        patchOp.setOperation(SCIMConstants.OperationalConstants.REPLACE);
        patchOp.setPath(path);
        patchOp.setValues(value);
        patchOperations.add(patchOp);
    }

    /**
     * Mask the given value if it is required.
     *
     * @param value Value to be masked.
     * @return Masked/unmasked value.
     */
    public static String maskIfRequired(String value) {

        return LoggerUtils.isLogMaskingEnable ? LoggerUtils.getMaskedContent(value) : value;
    }
}
