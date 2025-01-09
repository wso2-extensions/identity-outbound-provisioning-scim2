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

package org.wso2.carbon.identity.provisioning.connector.scim2;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningConstants;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;
import org.wso2.carbon.identity.provisioning.ProvisionedIdentifier;
import org.wso2.carbon.identity.provisioning.ProvisioningEntity;
import org.wso2.carbon.identity.provisioning.ProvisioningEntityType;
import org.wso2.carbon.identity.provisioning.ProvisioningOperation;
import org.wso2.carbon.identity.provisioning.ProvisioningUtil;
import org.wso2.carbon.identity.provisioning.connector.scim2.util.SCIMClaimResolver;
import org.wso2.carbon.identity.scim2.common.utils.SCIMCommonUtils;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.charon3.core.attributes.ComplexAttribute;
import org.wso2.charon3.core.attributes.DefaultAttributeFactory;
import org.wso2.charon3.core.attributes.MultiValuedAttribute;
import org.wso2.charon3.core.attributes.SimpleAttribute;
import org.wso2.charon3.core.exceptions.AbstractCharonException;
import org.wso2.charon3.core.exceptions.BadRequestException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.charon3.core.schema.SCIMSchemaDefinitions;
import org.wso2.scim2.client.ProvisioningClient;
import org.wso2.scim2.client.SCIMProvider;
import org.wso2.scim2.util.SCIM2CommonConstants;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * This class handles the SCIM2 user and group operations.
 */
public class SCIM2ProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final long serialVersionUID = -2800777564581005554L;
    private static final Log log = LogFactory.getLog(SCIM2ProvisioningConnector.class);
    private SCIMProvider scimProvider;
    private String userStoreDomainName;

    /**
     * Populates the SCIM2 configuration properties.
     *
     * @param provisioningProperties            Properties of the SCIM2 provisioning connector.
     * @throws IdentityProvisioningException    Error when initializing the connector.
     */
    @Override
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {

        scimProvider = new SCIMProvider();
        if (provisioningProperties != null && provisioningProperties.length > 0) {
            for (Property property : provisioningProperties) {
                if (SCIM2ProvisioningConnectorConstants.SCIM2_USER_EP.equals(property.getName())) {
                    populateSCIMProvider(property, SCIM2CommonConstants.ELEMENT_NAME_USER_ENDPOINT);
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_GROUP_EP.equals(property.getName())) {
                    populateSCIMProvider(property, SCIM2CommonConstants.ELEMENT_NAME_GROUP_ENDPOINT);
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME.equals(property.getName())) {
                    populateSCIMProvider(property, SCIMConstants.UserSchemaConstants.USER_NAME);
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_PASSWORD.equals(property.getName())) {
                    populateSCIMProvider(property, SCIMConstants.UserSchemaConstants.PASSWORD);
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_USERSTORE_DOMAIN.equals(property.getName())) {
                    userStoreDomainName = property.getValue() != null ? property.getValue()
                            : property.getDefaultValue();
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_ENABLE_PASSWORD_PROVISIONING.equals(property.
                        getName())) {
                    populateSCIMProvider(property, SCIM2ProvisioningConnectorConstants.
                            SCIM2_ENABLE_PASSWORD_PROVISIONING);
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_DEFAULT_PASSWORD.equals(property.getName())) {
                    populateSCIMProvider(property, SCIM2ProvisioningConnectorConstants.SCIM2_DEFAULT_PASSWORD);
                }

                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property
                        .getName()) && "1".equals(property.getValue())) {
                    jitProvisioningEnabled = true;
                }
            }
        }
    }

    /**
     * Initiates the SCIM2 operation.
     *
     * @param provisioningEntity    The entity to be provisioned through the connector.
     * @return provisionedEntity
     * @throws IdentityProvisioningException    Error when provisioning the entity.
     */
    @Override
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        if (provisioningEntity != null) {
            if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                log.debug("JIT provisioning disabled for SCIM 2.0 connector");
                return null;
            }

            if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                provisionUser(provisioningEntity);
            } else if (provisioningEntity.getEntityType() == ProvisioningEntityType.GROUP) {
                provisionGroup(provisioningEntity);
            } else {
                log.warn("Unsupported provisioning entity : " + provisioningEntity.getEntityName());
            }
        }
        return null;
    }

    private void provisionGroup(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
            deleteGroup(provisioningEntity);
        } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
            createGroup(provisioningEntity);
        } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
            updateGroup(provisioningEntity);
        } else {
            log.warn("Unsupported provisioning operation : " + provisioningEntity.getOperation() +
                    " for provisioning entity : " + provisioningEntity.getEntityName());
        }
    }

    private void provisionUser(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
            createUser(provisioningEntity);
        } else if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
            deleteUser(provisioningEntity);
        } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
            updateUser(provisioningEntity, ProvisioningOperation.PUT);
        } else {
            log.warn("Unsupported provisioning operation : " + provisioningEntity.getOperation() +
                    " for provisioning entity : " + provisioningEntity.getEntityName());
        }
    }

    /**
     * Creates the user.
     *
     * @param userEntity
     * @throws UserStoreException
     */
    private void createUser(ProvisioningEntity userEntity) throws IdentityProvisioningException {

        String userName = null;
        try {
            List<String> userNames = getUserNames(userEntity.getAttributes());
            if (CollectionUtils.isNotEmpty(userNames)) {
                userName = userNames.get(0);
            }
            // get single-valued claims
            Map<String, String> singleValued = getSingleValuedClaims(userEntity.getAttributes());
            // if user created through management console, claim values are not present.
            User user = (User) SCIMClaimResolver.constructSCIMObjectFromAttributes(singleValued, 1);
            user.setUserName(userName);
            setUserPassword(user, userEntity);

            ProvisioningClient scimProvsioningClient = new ProvisioningClient(scimProvider, user, null);
            scimProvsioningClient.provisionCreateUser();
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while creating the user : " + userName, e);
        }
    }

    /**
     * Deletes the user.
     *
     * @param userEntity
     * @throws IdentityProvisioningException
     */
    private void deleteUser(ProvisioningEntity userEntity) throws IdentityProvisioningException {

        String userName = null;
        try {
            List<String> userNames = getUserNames(userEntity.getAttributes());
            if (CollectionUtils.isNotEmpty(userNames)) {
                userName = userNames.get(0);
            }
            User user = new User();
            user.setUserName(userName);
            ProvisioningClient scimProvsioningClient = new ProvisioningClient(scimProvider, user, null);
            scimProvsioningClient.provisionDeleteUser();
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while deleting user : " + userName, e);
        }
    }

    /**
     * Updates the user.
     *
     * @param userEntity
     * @throws IdentityProvisioningException
     */
    private void updateUser(ProvisioningEntity userEntity, ProvisioningOperation provisioningOperation) throws
            IdentityProvisioningException {

        String userName = null;
        try {
            List<String> userNames = getUserNames(userEntity.getAttributes());
            if (CollectionUtils.isNotEmpty(userNames)) {
                userName = extractDomainFreeName(userNames.get(0));
            }
            User user;
            // get single-valued claims
            Map<String, String> singleValued = getSingleValuedClaims(userEntity.getAttributes());
            // if user created through management console, claim values are not present.
            if (MapUtils.isNotEmpty(singleValued)) {
                user = (User) SCIMClaimResolver.constructSCIMObjectFromAttributes(singleValued, 1);
            } else {
                user = new User();
            }
            user.setUserName(userName);
            ProvisioningClient scimProvisioningClient = new ProvisioningClient(scimProvider, user, null);
            if (ProvisioningOperation.PUT.equals(provisioningOperation)) {
                scimProvisioningClient.provisionUpdateUser();
            }
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while updating the user : " + userName, e);
        }
    }

    /**
     * Creates the group.
     *
     * @param groupEntity
     * @return
     * @throws IdentityProvisioningException
     */
    private String createGroup(ProvisioningEntity groupEntity) throws IdentityProvisioningException {

        String groupName = null;
        try {
            List<String> groupNames = getGroupNames(groupEntity.getAttributes());

            if (CollectionUtils.isNotEmpty(groupNames)) {
                groupName = groupNames.get(0);
            }
            Group group = new Group();
            group.setDisplayName(groupName);
            List<String> userList = getUserNames(groupEntity.getAttributes());
            setGroupMembers(group, userList);
            ProvisioningClient scimProvsioningClient = new ProvisioningClient(scimProvider, group, null);
            scimProvsioningClient.provisionCreateGroup();
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while adding group : " + groupName, e);
        }
        return null;
    }

    /**
     * Deletes the group.
     *
     * @param groupEntity
     * @throws IdentityProvisioningException
     */
    private void deleteGroup(ProvisioningEntity groupEntity) throws IdentityProvisioningException {

        String groupName = null;
        try {
            List<String> groupNames = getGroupNames(groupEntity.getAttributes());
            if (CollectionUtils.isNotEmpty(groupNames)) {
                groupName = groupNames.get(0);
            }

            Group group = new Group();
            group.setDisplayName(groupName);

            ProvisioningClient scimProvsioningClient = new ProvisioningClient(scimProvider, group, null);
            scimProvsioningClient.provisionDeleteGroup();
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while deleting group : " + groupName, e);
        }
    }

    /**
     * Updates the group.
     *
     * @param groupEntity
     * @throws IdentityProvisioningException
     */
    private void updateGroup(ProvisioningEntity groupEntity) throws IdentityProvisioningException {

        String oldGroupName = null;
        try {
            List<String> groupNames = getGroupNames(groupEntity.getAttributes());
            String groupName = null;
            if (CollectionUtils.isNotEmpty(groupNames)) {
                groupName = groupNames.get(0);
            }
            Group group = new Group();
            group.setDisplayName(groupName);
            List<String> userList = getUserNames(groupEntity.getAttributes());
            setGroupMembers(group, userList);

            oldGroupName = ProvisioningUtil.getAttributeValue(groupEntity,
                    IdentityProvisioningConstants.OLD_GROUP_NAME_CLAIM_URI);
            ProvisioningClient scimProvsioningClient;
            if (StringUtils.isEmpty(oldGroupName)) {
                scimProvsioningClient = new ProvisioningClient(scimProvider, group, null);
            } else {
                Map<String, Object> additionalInformation = new HashMap();
                additionalInformation.put(SCIM2CommonConstants.IS_ROLE_NAME_CHANGED_ON_UPDATE, true);
                additionalInformation.put(SCIM2CommonConstants.OLD_GROUP_NAME, oldGroupName);
                scimProvsioningClient = new ProvisioningClient(scimProvider, group, additionalInformation);
            }
            if (ProvisioningOperation.PUT.equals(groupEntity.getOperation())) {
                scimProvsioningClient.provisionUpdateGroup();
            }
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while updating group : " + oldGroupName, e);
        }
    }

    /**
     * Populates the SCIM Provider.
     *
     * @param property
     * @param scimPropertyName
     * @throws IdentityProvisioningException
     */
    private void populateSCIMProvider(Property property, String scimPropertyName)
            throws IdentityProvisioningException {

        if (StringUtils.isNotEmpty(property.getValue())) {
            scimProvider.setProperty(scimPropertyName, property.getValue());
        } else if (StringUtils.isNotEmpty(property.getDefaultValue())) {
            scimProvider.setProperty(scimPropertyName, property.getDefaultValue());
        }
    }

    /**
     * Returns the Claim dialect URIs.
     *
     * @return Scim dialects
     */
    @Override
    public String[] getClaimDialectUris() {

        return new String[]{SCIM2ProvisioningConnectorConstants.DEFAULT_SCIM2_CORE_DIALECT,
                SCIM2ProvisioningConnectorConstants.DEFAULT_SCIM2_USER_DIALECT,
                SCIM2ProvisioningConnectorConstants.DEFAULT_SCIM2_ENTERPRISE_DIALECT,
                SCIMCommonUtils.getCustomSchemaURI()};
    }

    /**
     * Sets the password.
     *
     * @param user
     * @param userEntity
     * @throws CharonException
     * @throws BadRequestException
     */
    private void setUserPassword(User user, ProvisioningEntity userEntity) throws CharonException, BadRequestException {

        if ("true".equals(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                SCIM2_ENABLE_PASSWORD_PROVISIONING))) {
            setPassword(user, getPassword(userEntity.getAttributes()));
        } else if (StringUtils.isNotBlank(scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.
                SCIM2_DEFAULT_PASSWORD))) {
            setPassword(user, scimProvider.getProperty(SCIM2ProvisioningConnectorConstants.SCIM2_DEFAULT_PASSWORD));
        }
    }

    /**
     * Sets the members to the group.
     *
     * @param group
     * @param userList
     * @throws AbstractCharonException
     */
    private void setGroupMembers(Group group, List<String> userList) throws AbstractCharonException {

        if (CollectionUtils.isNotEmpty(userList)) {
            for (Iterator<String> iterator = userList.iterator(); iterator.hasNext(); ) {
                String userName = iterator.next();
                this.setMember(group, userName);
            }
        }
    }

    /**
     * Sets the member to the group.
     *
     * @param group
     * @param userName
     * @throws BadRequestException
     * @throws CharonException
     */
    private void setMember(Group group, String userName) throws BadRequestException, CharonException {

        if (group.isAttributeExist(SCIMConstants.GroupSchemaConstants.MEMBERS)) {
            MultiValuedAttribute members = (MultiValuedAttribute) group.getAttributeList().get(
                    SCIMConstants.GroupSchemaConstants.MEMBERS);
            ComplexAttribute complexAttribute = setMemberCommon(userName);
            members.setAttributeValue(complexAttribute);
        } else {
            MultiValuedAttribute members = new MultiValuedAttribute(SCIMConstants.GroupSchemaConstants.MEMBERS);
            DefaultAttributeFactory.createAttribute(SCIMSchemaDefinitions.SCIMGroupSchemaDefinition.MEMBERS, members);
            ComplexAttribute complexAttribute = setMemberCommon(userName);
            members.setAttributeValue(complexAttribute);
            group.setAttribute(members);
        }
    }

    /**
     * Reurns the member complex attribute.
     *
     * @param userName
     * @return complex attribute
     * @throws BadRequestException
     * @throws CharonException
     */
    private ComplexAttribute setMemberCommon(String userName) throws BadRequestException, CharonException {

        ComplexAttribute complexAttribute = new ComplexAttribute();
        SimpleAttribute displaySimpleAttribute = new SimpleAttribute(SCIMConstants.GroupSchemaConstants.DISPLAY,
                userName);
        DefaultAttributeFactory.createAttribute(SCIMSchemaDefinitions.SCIMGroupSchemaDefinition.DISPLAY,
                displaySimpleAttribute);
        complexAttribute.setSubAttribute(displaySimpleAttribute);
        DefaultAttributeFactory.createAttribute(SCIMSchemaDefinitions.SCIMGroupSchemaDefinition.MEMBERS,
                complexAttribute);
        return complexAttribute;
    }

    /**
     * Sets the password for the user.
     *
     * @param user
     * @param password
     * @throws CharonException
     * @throws BadRequestException
     */
    private void setPassword(User user, String password) throws CharonException, BadRequestException {

        if (user.isAttributeExist(SCIMConstants.UserSchemaConstants.PASSWORD)) {
            ((SimpleAttribute) user.getAttributeList().get(SCIMConstants.UserSchemaConstants.PASSWORD)).
                    updateValue(password);
        } else {
            SimpleAttribute simpleAttribute = new SimpleAttribute(SCIMConstants.UserSchemaConstants.PASSWORD, password);
            simpleAttribute = (SimpleAttribute) DefaultAttributeFactory.
                    createAttribute(SCIMSchemaDefinitions.SCIMUserSchemaDefinition.PASSWORD, simpleAttribute);
            user.getAttributeList().put(SCIMConstants.UserSchemaConstants.PASSWORD, simpleAttribute);
        }
    }

    /**
     * Returns the UserStoreDomainName.
     *
     * @return UserStoreDomainName
     */
    @Override
    protected String getUserStoreDomainName() {
        return userStoreDomainName;
    }

    /**
     * Gets the domain free username.
     *
     * @param nameWithDomain Username with domain.
     * @return domainFreeName
     */
    private String extractDomainFreeName(String nameWithDomain) {

        int domainSeparatorIdx = nameWithDomain.indexOf(UserCoreConstants.DOMAIN_SEPARATOR);
        if (domainSeparatorIdx > 0) {
            String[] names = nameWithDomain.split(UserCoreConstants.DOMAIN_SEPARATOR);
            return names[1].trim();
        } else {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Domain is not available for username: %s. Therefore returning the " +
                        "original username.", nameWithDomain));
            }
            return nameWithDomain;
        }
    }
}
