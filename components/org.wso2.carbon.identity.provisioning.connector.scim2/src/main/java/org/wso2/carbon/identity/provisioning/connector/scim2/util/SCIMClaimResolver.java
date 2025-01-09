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

package org.wso2.carbon.identity.provisioning.connector.scim2.util;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.provisioning.connector.scim2.SCIM2ProvisioningConnectorConstants;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.charon3.core.attributes.Attribute;
import org.wso2.charon3.core.attributes.ComplexAttribute;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.attributes.DefaultAttributeFactory;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.exceptions.NotFoundException;
import org.wso2.charon3.core.exceptions.NotImplementedException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.objects.AbstractSCIMObject;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.SCIMObject;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.AttributeSchema;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMResourceSchemaManager;
import org.wso2.charon3.core.schema.SCIMSchemaDefinitions;
import org.wso2.charon3.core.schema.ResourceTypeSchema;
import org.wso2.charon3.core.schema.SCIMAttributeSchema;
import org.wso2.charon3.core.schema.SCIMDefinitions;
import org.wso2.charon3.core.utils.AttributeUtil;
import org.wso2.scim2.util.SCIM2CommonConstants;

import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
/**
 * This class is responsible for converting SCIM attributes in a SCIM object to carbon claims and vice versa.
 */
public class SCIMClaimResolver {

    private static final Log log = LogFactory.getLog(SCIMClaimResolver.class);
    private static final boolean debug = log.isDebugEnabled();

    /*
     * Return claims as a map of <ClaimUri (which is mapped to SCIM attribute uri),ClaimValue>
     *
     * @param scimObject
     * @return
     */
    public static Map<String, String> getClaimsMap(AbstractSCIMObject scimObject) throws CharonException {

        Map<String, String> claimsMap = new HashMap<>();
        Map<String, Attribute> attributeList = scimObject.getAttributeList();
        for (Map.Entry<String, Attribute> attributeEntry : attributeList.entrySet()) {
            Attribute attribute = attributeEntry.getValue();
            // if the attribute is password, skip it
            if (SCIMConstants.UserSchemaConstants.PASSWORD.equals(attribute.getName())) {
                continue;
            }
            if (attribute instanceof SimpleAttribute) {
                setClaimsForSimpleAttribute(attribute, claimsMap);
            } else if (attribute instanceof MultiValuedAttribute) {
                setClaimsForMultivaluedAttribute(attribute, claimsMap);
            } else if (attribute instanceof ComplexAttribute) {
                // NOTE: in carbon, we only support storing of type and value of a complex multi-valued attribute
                // reading attributes list of the complex attribute
                ComplexAttribute complexAttribute = (ComplexAttribute) attribute;
                Map<String, Attribute> attributes = null;
                if (complexAttribute.getSubAttributesList() != null &&
                        MapUtils.isNotEmpty(complexAttribute.getSubAttributesList())) {
                    attributes = complexAttribute.getSubAttributesList();
                }
                if (attributes != null) {
                    for (Attribute entry : attributes.values()) {
                        // if the attribute a simple attribute
                        if (entry instanceof SimpleAttribute) {
                            setClaimsForSimpleAttribute(entry, claimsMap);

                        } else if (entry instanceof MultiValuedAttribute) {
                            setClaimsForMultivaluedAttribute(entry, claimsMap);

                        } else if (entry instanceof ComplexAttribute) {
                            setClaimsForComplexAttribute(entry, claimsMap);
                        }
                    }
                }
            }
        }
        return claimsMap;
    }

    /*
     * Set claim mapping for simple attribute.
     *
     * @param attribute
     * @param claimsMap
     */
    private static void setClaimsForSimpleAttribute(Attribute attribute, Map<String, String> claimsMap) throws
            CharonException {

        String attributeURI = attribute.getURI();
        if (((SimpleAttribute) attribute).getValue() != null) {
            String attributeValue = AttributeUtil.getStringValueOfAttribute(
                    ((SimpleAttribute) attribute).getValue(), attribute.getType());
            // set attribute URI as the claim URI
            claimsMap.put(attributeURI, attributeValue);
        }
    }

    /*
     * Set claim mapping for multivalued attribute.
     *
     * @param attribute
     * @param claimsMap
     */
    private static void setClaimsForMultivaluedAttribute(Attribute attribute, Map<String, String> claimsMap) throws
            CharonException {

        MultiValuedAttribute multiValAttribute = (MultiValuedAttribute) attribute;
        // get the URI of root attribute
        String attributeURI = multiValAttribute.getURI();
        // check if values are set as primitive values
        List<Object> attributeValues = multiValAttribute.getAttributePrimitiveValues();
        if (CollectionUtils.isNotEmpty(attributeValues)) {
            String values = null;
            for (Object attributeValue : attributeValues) {
                if (values != null) {
                    values += attributeValue + ",";
                } else {
                    values = attributeValue + ",";
                }
            }
            claimsMap.put(attributeURI, values);
        }
        // check if values are set as complex values
        // NOTE: in carbon, we only support storing of type and
        // value of a multi-valued attribute
        List<Attribute> complexAttributeList = multiValAttribute.getAttributeValues();
        for (Attribute complexAttrib : complexAttributeList) {
            Map<String, Attribute> subAttributes =
                    ((ComplexAttribute) complexAttrib).getSubAttributesList();
            SimpleAttribute typeAttribute =
                    (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.TYPE);
            String valueAttriubuteURI;
            // construct attribute URI
            if (typeAttribute != null) {
                String typeValue = (String) typeAttribute.getValue();
                valueAttriubuteURI = attributeURI + "." + typeValue;
            } else {
                valueAttriubuteURI = attributeURI;
            }
            SimpleAttribute valueAttribute = null;
            if (attribute.getName().equals(SCIMConstants.UserSchemaConstants.ADDRESSES)) {
                valueAttribute =
                        (SimpleAttribute) subAttributes.get(SCIMConstants.UserSchemaConstants.FORMATTED_ADDRESS);
            } else {
                valueAttribute =
                        (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.VALUE);
            }
            if (valueAttribute != null && valueAttribute.getValue() != null) {
                // put it in claims
                claimsMap.put(valueAttriubuteURI,
                        AttributeUtil.getStringValueOfAttribute(valueAttribute.getValue(), valueAttribute.getType()));
            }
        }
    }

    /*
     * Set claim mapping for complex attribute.
     *
     * @param entry
     * @param claimsMap
     */
    private static void setClaimsForComplexAttribute(Attribute entry, Map<String, String> claimsMap) throws
            CharonException {

        // reading attributes list of the complex attribute
        ComplexAttribute entryOfComplexAttribute = (ComplexAttribute) entry;
        Map<String, Attribute> entryAttributes;
        if (entryOfComplexAttribute.getSubAttributesList() != null &&
                MapUtils.isNotEmpty(entryOfComplexAttribute.getSubAttributesList())) {
            entryAttributes = entryOfComplexAttribute.getSubAttributesList();
            for (Attribute subEntry : entryAttributes.values()) {
                // attribute can only be simple attribute and that also in the extension schema only
                if (subEntry.getMultiValued()) {
                    setClaimsForMultivaluedAttribute(subEntry, claimsMap);
                } else {
                    setClaimsForSimpleAttribute(subEntry, claimsMap);
                }
            }
        }
    }

    /*
     * Construct the SCIM Object given the attribute URIs and attribute values of the object.
     *
     * @param attributes
     * @param scimObjectType
     * @return
     */
    public static SCIMObject constructSCIMObjectFromAttributes(Map<String, String> attributes, int scimObjectType)
            throws CharonException, NotFoundException, BadRequestException {

        SCIMObject scimObject = null;
        switch (scimObjectType) {
            case SCIM2CommonConstants.GROUP:
                scimObject = new Group();
                if (debug) {
                    log.debug("Building Group Object");
                }
                break;
            case SCIM2CommonConstants.USER:
                scimObject = new User();
                if (debug) {
                    log.debug("Building User Object");
                }
                break;
            default:
                break;
        }

        for (Map.Entry<String, String> attributeEntry : attributes.entrySet()) {
            if (debug) {
                log.info("AttributeKey: " + attributeEntry.getKey() + " AttributeValue:" +
                        attributeEntry.getValue());
            }
            String attributeURI = attributeEntry.getKey();
            String[] attributeNames;

            if (attributeURI.contains(SCIMConstants.CORE_SCHEMA_URI)) {
                String[] attributeURIParts = attributeURI.split(":");
                String attributeNameString = attributeURIParts[attributeURIParts.length - 1];
                attributeNames = attributeNameString.split("\\.");
            } else {
                ArrayList<String> tempAttributeNames = new ArrayList<>();
                String extensionURI = "";
                String[] attributeURIParts = attributeURI.split(":");
                for (int i = 0; i < attributeURIParts.length - 1; i++) {
                    extensionURI = extensionURI + ":" + attributeURIParts[i];
                }
                String attributeNameString = attributeURIParts[attributeURIParts.length - 1];
                attributeNames = attributeNameString.split("\\.");
                tempAttributeNames.add(extensionURI.substring(1));

                for (int i = 0; i < attributeNames.length; i++) {
                    tempAttributeNames.add(attributeNames[i]);
                }
                attributeNames = tempAttributeNames.toArray(attributeNames);
            }

            if (attributeNames.length == 1) {
                constructSCIMObjectFromAttributesOfLevelOne(attributeEntry, scimObject, attributeNames, scimObjectType);
            } else if (attributeNames.length == 2) {
                constructSCIMObjectFromAttributesOfLevelTwo(attributeEntry, scimObject, attributeNames, scimObjectType);
            } else if (attributeNames.length == 3) {
                constructSCIMObjectFromAttributesOfLevelThree(attributeEntry, scimObject, attributeNames,
                        scimObjectType);
            }
        }
        return scimObject;
    }

    /*
     * Construct the level one attributes like nickName.
     *
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     */
    public static void constructSCIMObjectFromAttributesOfLevelOne(Map.Entry<String, String> attributeEntry,
                                                                   SCIMObject scimObject, String[] attributeNames,
                                                                   int scimObjectType)
            throws BadRequestException, CharonException {

        //get attribute schema
        AttributeSchema attributeSchema = getAttributeSchema(attributeEntry.getKey(), scimObjectType);
        if (attributeSchema != null) {
            //either simple valued or multi-valued with simple attributes
            if (attributeSchema.getMultiValued()) {
                //see whether multiple values are there
                String value = attributeEntry.getValue();
                Object[] values = value.split(",");
                //create attribute
                MultiValuedAttribute multiValuedAttribute = new MultiValuedAttribute(attributeSchema.getName());
                //set values
                multiValuedAttribute.setAttributePrimitiveValues(Arrays.asList(values));
                //set attribute in scim object
                DefaultAttributeFactory.createAttribute(attributeSchema, multiValuedAttribute);
                ((AbstractSCIMObject) scimObject).setAttribute(multiValuedAttribute);
            } else {
                //convert attribute to relevant type
                Object attributeValueObject = AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                        attributeSchema.getType());
                //create attribute
                SimpleAttribute simpleAttribute = new SimpleAttribute(attributeNames[0], attributeValueObject);
                DefaultAttributeFactory.createAttribute(attributeSchema, simpleAttribute);
                //set attribute in the SCIM object
                ((AbstractSCIMObject) scimObject).setAttribute(simpleAttribute);
            }
        }
    }

    /*
     * Construct the level two attributes like emails.
     *
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     * @throws NotFoundException
     */
    public static void constructSCIMObjectFromAttributesOfLevelTwo(Map.Entry<String, String> attributeEntry,
                                                                   SCIMObject scimObject, String[] attributeNames,
                                                                   int scimObjectType)
            throws BadRequestException, CharonException, NotFoundException {

        //get parent attribute name
        String parentAttributeName = attributeNames[0];
        //get parent attribute schema
        String parentAttributeURI = attributeEntry.getKey().replace("." + attributeNames[1], "");
        if (parentAttributeURI.equals(attributeEntry.getKey())) {
            parentAttributeURI = attributeEntry.getKey().replace(":" + attributeNames[1], "");
        }
        AttributeSchema parentAttributeSchema = getAttributeSchema(parentAttributeURI, scimObjectType);
        // differentiate between sub attribute of Complex attribute and a Multivalued attribute with complex value
        if (parentAttributeSchema.getMultiValued()) {
            constructSCIMObjectFromMultiValuedAttributesOfLevelTwo(attributeEntry, scimObject, attributeNames[1],
                    scimObjectType, parentAttributeName, parentAttributeSchema);

        } else {
            constructSCIMObjectFromSingleValuedAttributesOfLevelTwo(attributeEntry, scimObject, attributeNames[1],
                    getAttributeSchema(attributeEntry.getKey(), scimObjectType), parentAttributeSchema);

        }
    }

    private static void constructSCIMObjectFromSingleValuedAttributesOfLevelTwo(
            Map.Entry<String, String> attributeEntry, SCIMObject scimObject, String attributeName,
            AttributeSchema attributeSchema, AttributeSchema parentAttributeSchema) throws CharonException,
            BadRequestException, NotFoundException {

        //sub attribute of a complex attribute
        AttributeSchema subAttributeSchema = attributeSchema;
        //we assume sub attribute is simple attribute
        SimpleAttribute simpleAttribute = new SimpleAttribute(attributeName, AttributeUtil.
                getAttributeValueFromString(attributeEntry.getValue(), subAttributeSchema.getType()));
        DefaultAttributeFactory.createAttribute(subAttributeSchema, simpleAttribute);
        //check whether parent attribute exists.
        if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeSchema.getName())) {
            ComplexAttribute complexAttribute = (ComplexAttribute) scimObject.getAttribute(parentAttributeSchema.
                    getName());
            complexAttribute.setSubAttribute(simpleAttribute);
        } else {
            //create parent attribute and set sub attribute
            ComplexAttribute complexAttribute = new ComplexAttribute(parentAttributeSchema.getName());
            complexAttribute.setSubAttribute(simpleAttribute);
            DefaultAttributeFactory.createAttribute(parentAttributeSchema, complexAttribute);
            ((AbstractSCIMObject) scimObject).setAttribute(complexAttribute);
        }
    }

    private static void constructSCIMObjectFromMultiValuedAttributesOfLevelTwo(
            Map.Entry<String, String> attributeEntry, SCIMObject scimObject, String attributeName, int scimObjectType,
            String parentAttributeName, AttributeSchema parentAttributeSchema) throws CharonException,
            BadRequestException, NotFoundException {

        //get the value sub attribute
        String valueAttributeURI = attributeEntry.getKey().replace("." + attributeName, "");
        AttributeSchema valueSubAttributeSchema;
        if (valueAttributeURI.equals(SCIMConstants.UserSchemaConstants.ADDRESSES_URI)) {
            valueAttributeURI = valueAttributeURI + ".formatted";
            valueSubAttributeSchema = getAttributeSchema(valueAttributeURI, scimObjectType);
        } else {
            valueAttributeURI = valueAttributeURI + SCIM2ProvisioningConnectorConstants.ATTRIBUTE_VALUE;
            valueSubAttributeSchema = getAttributeSchema(valueAttributeURI, scimObjectType);
        }
        //create map with complex value
        SimpleAttribute typeSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE,
                attributeName);

        String typeAttributeURI = attributeEntry.getKey().replace("." + attributeName, "");
        typeAttributeURI = typeAttributeURI + SCIM2ProvisioningConnectorConstants.ATTRIBUTE_TYPE;
        AttributeSchema typeAttributeSchema = getAttributeSchema(typeAttributeURI, scimObjectType);
        DefaultAttributeFactory.createAttribute(typeAttributeSchema, typeSimpleAttribute);
        SimpleAttribute valueSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.VALUE,
                AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                        valueSubAttributeSchema.getType()));
        DefaultAttributeFactory.createAttribute(valueSubAttributeSchema, valueSimpleAttribute);

        //need to set a complex type value for multivalued attribute
        Object type = SCIM2ProvisioningConnectorConstants.DEFAULT;
        Object value = SCIM2ProvisioningConnectorConstants.DEFAULT;

        if (typeSimpleAttribute.getValue() != null) {
            type = typeSimpleAttribute.getValue();
        }
        if (valueSimpleAttribute.getValue() != null) {
            value = valueSimpleAttribute.getValue();
        }
        String complexName = parentAttributeName + "_" + value + "_" + type;
        ComplexAttribute complexAttribute = new ComplexAttribute(complexName);
        complexAttribute.setSubAttribute(typeSimpleAttribute);
        complexAttribute.setSubAttribute(valueSimpleAttribute);
        DefaultAttributeFactory.createAttribute(parentAttributeSchema, complexAttribute);

        //check whether parent multivalued attribute already exists
        if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeName)) {
            //create attribute value as complex value
            MultiValuedAttribute multiValuedAttribute =
                    (MultiValuedAttribute) scimObject.getAttribute(parentAttributeName);
            multiValuedAttribute.setAttributeValue(complexAttribute);
        } else {
            //create the attribute and set it in the scim object
            MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(
                    parentAttributeName);
            multivaluedAttribute.setAttributeValue(complexAttribute);
            DefaultAttributeFactory.createAttribute(parentAttributeSchema, multivaluedAttribute);
            ((AbstractSCIMObject) scimObject).setAttribute(multivaluedAttribute);
        }
    }

    /*
     * Construct the level three extension attributes like extensionSchema.manager.id
     *
     * @param attributeEntry
     * @param scimObject
     * @param attributeNames
     * @param scimObjectType
     * @throws BadRequestException
     * @throws CharonException
     */
    public static void constructSCIMObjectFromAttributesOfLevelThree(Map.Entry<String, String> attributeEntry,
                                                                     SCIMObject scimObject, String[] attributeNames,
                                                                     int scimObjectType) throws BadRequestException,
            CharonException {

        String parentAttribute = attributeNames[0];
        //get immediate parent attribute name
        String immediateParentAttributeName = attributeNames[1];
        String subAttributeURI = attributeEntry.getKey().replace("." + attributeNames[2], "");
        String parentAttributeURI = subAttributeURI.replace(":" + attributeNames[1], "");
        AttributeSchema subAttributeSchema = getAttributeSchema(subAttributeURI, scimObjectType);
        AttributeSchema attributeSchema = getAttributeSchema(parentAttributeURI, scimObjectType);
        // differentiate between sub attribute of Complex attribute and a Multivalued attribute with complex value
        if (subAttributeSchema.getMultiValued()) {
            constructSCIMObjectFromMultiValuedAttributesOfLevelThree(attributeEntry, (AbstractSCIMObject) scimObject,
                    attributeNames, scimObjectType, parentAttribute, immediateParentAttributeName, subAttributeSchema,
                    attributeSchema);
        } else {
            constructSCIMObjectFromSingleValuedAttributesOfLevelThree(attributeEntry, (AbstractSCIMObject) scimObject,
                    attributeNames, scimObjectType, immediateParentAttributeName, parentAttributeURI,
                    subAttributeSchema);
        }
    }

    private static void constructSCIMObjectFromSingleValuedAttributesOfLevelThree(
            Map.Entry<String, String> attributeEntry, AbstractSCIMObject scimObject, String[] attributeNames,
            int scimObjectType, String immediateParentAttributeName, String parentAttributeURI,
            AttributeSchema subAttributeSchema) throws CharonException, BadRequestException {

        AttributeSchema subSubAttributeSchema = getAttributeSchema(attributeEntry.getKey(), scimObjectType);
        //we assume sub attribute is simple attribute
        SimpleAttribute simpleAttribute = new SimpleAttribute(attributeNames[2],
                AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                        subSubAttributeSchema.getType()));
        DefaultAttributeFactory.createAttribute(subSubAttributeSchema, simpleAttribute);

        // check if the super parent exist
        boolean superParentExist = scimObject.isAttributeExist(attributeNames[0]);
        if (superParentExist) {
            ComplexAttribute superParentAttribute = (ComplexAttribute) scimObject
                    .getAttribute(attributeNames[0]);
            // check if the immediate parent exist
            boolean immediateParentExist = superParentAttribute.isSubAttributeExist(immediateParentAttributeName);
            if (immediateParentExist) {
                // both the parent and super parent exists
                ComplexAttribute immediateParentAttribute = (ComplexAttribute) superParentAttribute
                        .getSubAttribute(immediateParentAttributeName);
                immediateParentAttribute.setSubAttribute(simpleAttribute);
            } else { // immediate parent does not exist
                ComplexAttribute immediateParentAttribute = new ComplexAttribute(immediateParentAttributeName);
                immediateParentAttribute.setSubAttribute(simpleAttribute);
                DefaultAttributeFactory.createAttribute(subAttributeSchema, immediateParentAttribute);
                // created the immediate parent and now set to super
                superParentAttribute.setSubAttribute(immediateParentAttribute);
            }
        } else { // now have to create both the super parent and immediate parent
            // immediate first
            ComplexAttribute immediateParentAttribute = new ComplexAttribute(immediateParentAttributeName);
            immediateParentAttribute.setSubAttribute(simpleAttribute);
            DefaultAttributeFactory.createAttribute(subAttributeSchema, immediateParentAttribute);
            // now super parent
            AttributeSchema superParentAttributeSchema = getAttributeSchema(parentAttributeURI, scimObjectType);
            ComplexAttribute superParentAttribute = new ComplexAttribute(superParentAttributeSchema.getName());
            superParentAttribute.setSubAttribute(immediateParentAttribute);
            DefaultAttributeFactory.createAttribute(superParentAttributeSchema, superParentAttribute);
            // now add the super to the scim object
            scimObject.setAttribute(superParentAttribute);
        }
    }

    private static void constructSCIMObjectFromMultiValuedAttributesOfLevelThree(
            Map.Entry<String, String> attributeEntry, AbstractSCIMObject scimObject, String[] attributeNames,
            int scimObjectType, String parentAttribute, String immediateParentAttributeName,
            AttributeSchema subAttributeSchema, AttributeSchema attributeSchema) throws CharonException,
            BadRequestException {

        SimpleAttribute typeSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE,
                attributeNames[2]);
        AttributeSchema typeAttributeSchema = getAttributeSchema(subAttributeSchema.getURI() +
                        SCIM2ProvisioningConnectorConstants.ATTRIBUTE_TYPE, scimObjectType);
        DefaultAttributeFactory.createAttribute(typeAttributeSchema, typeSimpleAttribute);
        AttributeSchema valueAttributeSchema = getAttributeSchema(subAttributeSchema.getURI() +
                        SCIM2ProvisioningConnectorConstants.ATTRIBUTE_VALUE, scimObjectType);
        SimpleAttribute valueSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.VALUE,
                AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(), valueAttributeSchema.getType
                        ()));
        DefaultAttributeFactory.createAttribute(valueAttributeSchema, valueSimpleAttribute);

        //need to set a complex type value for multivalued attribute
        Object type = SCIM2ProvisioningConnectorConstants.DEFAULT;
        Object value = SCIM2ProvisioningConnectorConstants.DEFAULT;

        if (typeSimpleAttribute.getValue() != null) {
            type = typeSimpleAttribute.getValue();
        }
        if (valueSimpleAttribute.getValue() != null) {
            value = valueSimpleAttribute.getValue();
        }
        String complexName = immediateParentAttributeName + "_" + value + "_" + type;
        ComplexAttribute complexAttribute = new ComplexAttribute(complexName);
        complexAttribute.setSubAttribute(typeSimpleAttribute);
        complexAttribute.setSubAttribute(valueSimpleAttribute);
        DefaultAttributeFactory.createAttribute(subAttributeSchema, complexAttribute);

        ComplexAttribute extensionComplexAttribute = null;

        if (scimObject.isAttributeExist(parentAttribute)) {
            Attribute extensionAttribute = scimObject.getAttribute(parentAttribute);
            extensionComplexAttribute = ((ComplexAttribute) extensionAttribute);
        } else {
            extensionComplexAttribute = new ComplexAttribute(parentAttribute);
            DefaultAttributeFactory.createAttribute(attributeSchema, extensionComplexAttribute);
            scimObject.setAttribute(extensionComplexAttribute);
        }

        Map<String, Attribute> extensionSubAttributes = extensionComplexAttribute.getSubAttributesList();
        if (extensionSubAttributes.containsKey(attributeNames[1])) {
            //create attribute value as complex value
            MultiValuedAttribute multiValuedAttribute =
                    (MultiValuedAttribute) extensionSubAttributes.get(attributeNames[1]);
            multiValuedAttribute.setAttributeValue(complexAttribute);
        } else {
            //create the attribute and set it in the scim object
            MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(attributeNames[1]);
            multivaluedAttribute.setAttributeValue(complexAttribute);
            DefaultAttributeFactory.createAttribute(subAttributeSchema, multivaluedAttribute);
            extensionComplexAttribute.setSubAttribute(multivaluedAttribute);
        }
    }

    /*
     * Return the attribute schema for the asked attribute URI.
     *
     * @param attributeURI
     * @param scimObjectType
     * @return
     */
    private static AttributeSchema getAttributeSchema(String attributeURI, int scimObjectType) {

        ResourceTypeSchema resourceSchema = getResourceSchema(scimObjectType);
        if (resourceSchema != null) {
            List<AttributeSchema> attributeSchemas = resourceSchema.getAttributesList();
            for (AttributeSchema attributeSchema : attributeSchemas) {
                if (attributeURI.equals(attributeSchema.getURI())) {
                    return attributeSchema;
                }
                if (attributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)) {
                    if (attributeSchema.getMultiValued()) {
                        List<AttributeSchema> subAttributeSchemaList = attributeSchema.getSubAttributeSchemas();
                        for (AttributeSchema subAttributeSchema : subAttributeSchemaList) {
                            if (attributeURI.equals(subAttributeSchema.getURI())) {
                                return subAttributeSchema;
                            }
                        }
                    } else {
                        List<AttributeSchema> subAttributeSchemaList = attributeSchema.getSubAttributeSchemas();
                        for (AttributeSchema subAttributeSchema : subAttributeSchemaList) {
                            if (attributeURI.equals(subAttributeSchema.getURI())) {
                                return subAttributeSchema;
                            }
                            if (subAttributeSchema.getType().equals(SCIMDefinitions.DataType.COMPLEX)) {
                                // this is only valid for extension schema
                                List<AttributeSchema> subSubAttributeSchemaList = subAttributeSchema
                                        .getSubAttributeSchemas();
                                for (AttributeSchema subSubAttributeSchema : subSubAttributeSchemaList) {
                                    if (attributeURI.equals(subSubAttributeSchema.getURI())) {
                                        return subSubAttributeSchema;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    /*
     * Return the corresponding resource type schema.
     *
     * @param scimObjectType
     * @return
     */
    private static ResourceTypeSchema getResourceSchema(int scimObjectType) {

        ResourceTypeSchema resourceSchema = null;
        switch (scimObjectType) {
            case 1:
                try {
                    UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();
                    resourceSchema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema(userManager);
                } catch (CharonException | BadRequestException | NotImplementedException e) {
                    log.debug("Error in getting user resource schema with user manager.", e);
                    resourceSchema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
                }
                break;
            case 2:
                resourceSchema = SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA;
                break;
            default:
                break;
        }
        return resourceSchema;
    }
}
