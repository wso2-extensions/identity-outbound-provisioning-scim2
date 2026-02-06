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
import org.wso2.carbon.identity.provisioning.connector.scim2.util.SCIM2ConnectorUtil;
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
import org.wso2.charon3.core.utils.codeutils.PatchOperation;
import org.wso2.scim2.client.ProvisioningClient;
import org.wso2.scim2.client.SCIMProvider;
import org.wso2.scim2.util.AuthenticationType;
import org.wso2.scim2.util.SCIM2CommonConstants;

import java.util.ArrayList;
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
    private String authenticationType;

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
            // First pass: extract authentication type and credentials
            String username = null;
            String password = null;
            String accessToken = null;
            String apiKeyHeader = null;
            String apiKeyValue = null;

            for (Property property : provisioningProperties) {
                if (SCIM2ProvisioningConnectorConstants.SCIM2_USER_EP.equals(property.getName())) {
                    populateSCIMProvider(property, SCIM2CommonConstants.ELEMENT_NAME_USER_ENDPOINT);
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_GROUP_EP.equals(property.getName())) {
                    populateSCIMProvider(property, SCIM2CommonConstants.ELEMENT_NAME_GROUP_ENDPOINT);
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_AUTHENTICATION_MODE.equals(property.getName())) {
                    authenticationType = property.getValue() != null ? property.getValue() :
                            property.getDefaultValue();
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_USERNAME.equals(property.getName())) {
                    username = property.getValue() != null ? property.getValue() : property.getDefaultValue();
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_PASSWORD.equals(property.getName())) {
                    password = property.getValue() != null ? property.getValue() : property.getDefaultValue();
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_ACCESS_TOKEN.equals(property.getName())) {
                    accessToken = property.getValue() != null ? property.getValue() : property.getDefaultValue();
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_API_KEY_HEADER.equals(property.getName())) {
                    apiKeyHeader = property.getValue() != null ? property.getValue() : property.getDefaultValue();
                } else if (SCIM2ProvisioningConnectorConstants.SCIM2_API_KEY_VALUE.equals(property.getName())) {
                    apiKeyValue = property.getValue() != null ? property.getValue() : property.getDefaultValue();
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

            // Configure authentication based on type.
            configureAuthentication(username, password, accessToken, apiKeyHeader, apiKeyValue);
        }
    }

    /**
     * Configure authentication on the SCIM provider based on authentication type.
     *
     * @param username       Username for BASIC auth.
     * @param password       Password for BASIC auth.
     * @param accessToken    Access token for BEARER auth.
     * @param apiKeyHeader   API key header name for API_KEY auth.
     * @param apiKeyValue    API key value for API_KEY auth.
     */
    private void configureAuthentication(String username, String password, String accessToken,
                                        String apiKeyHeader, String apiKeyValue) {

        // Parse authentication type from string value, default to BASIC if not specified.
        AuthenticationType authType = StringUtils.isBlank(authenticationType) ?
                AuthenticationType.BASIC : AuthenticationType.fromValue(authenticationType);

        switch (authType) {
            case BASIC:
                if (StringUtils.isNotBlank(username) && StringUtils.isNotBlank(password)) {
                    scimProvider.setProperty(SCIMConstants.UserSchemaConstants.USER_NAME, username);
                    scimProvider.setProperty(SCIMConstants.UserSchemaConstants.PASSWORD, password);
                    scimProvider.setProperty(SCIM2CommonConstants.AUTHENTICATION_TYPE, authType.getValue());
                } else {
                    log.warn("BASIC authentication requires both username and password. " +
                            "Skipping authentication configuration.");
                }
                break;
            case BEARER:
                if (StringUtils.isNotBlank(accessToken)) {
                    scimProvider.setProperty(SCIM2CommonConstants.ACCESS_TOKEN, accessToken);
                    scimProvider.setProperty(SCIM2CommonConstants.AUTHENTICATION_TYPE, authType.getValue());
                } else {
                    log.warn("BEARER authentication requires an access token. " +
                            "Skipping authentication configuration.");
                }
                break;
            case API_KEY:
                if (StringUtils.isNotBlank(apiKeyHeader) && StringUtils.isNotBlank(apiKeyValue)) {
                    scimProvider.setProperty(SCIM2CommonConstants.API_KEY_HEADER, apiKeyHeader);
                    scimProvider.setProperty(SCIM2CommonConstants.API_KEY_VALUE, apiKeyValue);
                    scimProvider.setProperty(SCIM2CommonConstants.AUTHENTICATION_TYPE, authType.getValue());
                } else {
                    log.warn("API_KEY authentication requires both header name and value. " +
                            "Skipping authentication configuration.");
                }
                break;
            case NONE:
                scimProvider.setProperty(SCIM2CommonConstants.AUTHENTICATION_TYPE, authType.getValue());
                if (log.isDebugEnabled()) {
                    log.debug("No authentication configured for SCIM2 provisioning");
                }
                break;
            default:
                log.warn("Unsupported authentication type: " + authenticationType + ". " +
                        "Skipping authentication configuration.");
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

        switch (provisioningEntity.getOperation()) {
            case POST:
                createGroup(provisioningEntity);
                break;
            case DELETE:
                deleteGroup(provisioningEntity);
                break;
            case PUT:
                updateGroup(provisioningEntity, ProvisioningOperation.PUT);
                break;
            case PATCH:
                updateGroup(provisioningEntity, ProvisioningOperation.PATCH);
                break;
            default:
                log.warn("Unsupported provisioning operation : " + provisioningEntity.getOperation() +
                        " for provisioning entity : " + provisioningEntity.getEntityName());
                break;
        }
    }

    private void provisionUser(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        switch (provisioningEntity.getOperation()) {
            case POST:
                createUser(provisioningEntity);
                break;
            case DELETE:
                deleteUser(provisioningEntity);
                break;
            case PUT:
                updateUser(provisioningEntity, ProvisioningOperation.PUT);
                break;
            case PATCH:
                updateUser(provisioningEntity, ProvisioningOperation.PATCH);
                break;
            default:
                log.warn("Unsupported provisioning operation : " + provisioningEntity.getOperation() +
                        " for provisioning entity : " + provisioningEntity.getEntityName());
                break;
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
            // Get single-valued claims.
            Map<String, String> singleValued = getSingleValuedClaims(userEntity.getAttributes());
            if (MapUtils.isEmpty(singleValued)) {
                if (log.isDebugEnabled()) {
                    log.debug("Skipping user provisioning. No claims found for user: " +
                            SCIM2ConnectorUtil.maskIfRequired(userName));
                }
                return;
            }
            User user = SCIM2ConnectorUtil.constructUserFromAttributes(singleValued);
            user.setUserName(userName);
            setUserPassword(user, userEntity);

            ProvisioningClient scimProvisioningClient = new ProvisioningClient(scimProvider, user, null);
            scimProvisioningClient.provisionCreateUser();
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while creating the user : " +
                    SCIM2ConnectorUtil.maskIfRequired(userName), e);
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
            throw new IdentityProvisioningException("Error while deleting user : " +
                    SCIM2ConnectorUtil.maskIfRequired(userName), e);
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

            // Get single-valued claims.
            Map<String, String> singleValued = getSingleValuedClaims(userEntity.getAttributes());
            if (MapUtils.isEmpty(singleValued)) {
                if (log.isDebugEnabled()) {
                    log.debug("Skipping user provisioning. No claims found for user: " +
                            SCIM2ConnectorUtil.maskIfRequired(userName));
                }
                return;
            }

            // Determine whether to use PATCH based on configuration.
            boolean shouldUsePatch = ProvisioningOperation.PATCH.equals(provisioningOperation) ||
                    SCIM2ConnectorUtil.isSCIMPatchEnabledForUpdates();

            User user;
            if (shouldUsePatch) {
                // For PATCH operation, construct User object and convert its attributes to patch operations.
                if (MapUtils.isNotEmpty(singleValued)) {
                    user = SCIM2ConnectorUtil.constructUserFromAttributes(singleValued);
                } else {
                    user = new User();
                }
                user.setUserName(userName);

                Map<String, Object> additionalInformation = new HashMap<>();
                List<PatchOperation> patchOperations = SCIM2ConnectorUtil.buildPatchOperationsFromUser(user);

                if (CollectionUtils.isEmpty(patchOperations)) {
                    log.warn("No patch operations to perform for user: " +
                            SCIM2ConnectorUtil.maskIfRequired(userName));
                    return;
                }

                additionalInformation.put(SCIM2CommonConstants.PATCH_OPERATIONS, patchOperations);
                ProvisioningClient scimProvisioningClient = new ProvisioningClient(scimProvider, user,
                        additionalInformation);
                scimProvisioningClient.provisionPatchUser();
            } else if (ProvisioningOperation.PUT.equals(provisioningOperation)) {
                // For PUT operation (when PATCH is disabled), construct full User object.
                if (MapUtils.isNotEmpty(singleValued)) {
                    user = SCIM2ConnectorUtil.constructUserFromAttributes(singleValued);
                } else {
                    user = new User();
                }
                user.setUserName(userName);
                ProvisioningClient scimProvisioningClient = new ProvisioningClient(scimProvider, user, null);
                scimProvisioningClient.provisionUpdateUser();
            }
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while updating the user : " +
                    SCIM2ConnectorUtil.maskIfRequired(userName), e);
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
     * @param provisioningOperation
     * @throws IdentityProvisioningException
     */
    private void updateGroup(ProvisioningEntity groupEntity, ProvisioningOperation provisioningOperation) throws
            IdentityProvisioningException {

        String groupName = null;
        String oldGroupName = null;
        try {
            List<String> groupNames = getGroupNames(groupEntity.getAttributes());
            if (CollectionUtils.isNotEmpty(groupNames)) {
                groupName = groupNames.get(0);
            }

            Group group = new Group();
            group.setDisplayName(groupName);
            List<String> userList = getUserNames(groupEntity.getAttributes());
            setGroupMembers(group, userList);

            oldGroupName = ProvisioningUtil.getAttributeValue(groupEntity,
                    IdentityProvisioningConstants.OLD_GROUP_NAME_CLAIM_URI);
            ProvisioningClient scimProvisioningClient;

            // Determine whether to use PATCH based on configuration.
            boolean shouldUsePatch = ProvisioningOperation.PATCH.equals(provisioningOperation) ||
                    SCIM2ConnectorUtil.isSCIMPatchEnabledForUpdates();

            if (shouldUsePatch) {
                Map<String, Object> additionalInformation = new HashMap<>();

                // Handle member updates via PATCH.
                List<String> newUsers = ProvisioningUtil.getClaimValues(groupEntity.getAttributes(),
                        IdentityProvisioningConstants.NEW_USER_CLAIM_URI, getUserStoreDomainName());
                List<String> deletedUsers = ProvisioningUtil.getClaimValues(groupEntity.getAttributes(),
                        IdentityProvisioningConstants.DELETED_USER_CLAIM_URI, getUserStoreDomainName());

                if (CollectionUtils.isNotEmpty(newUsers)) {
                    additionalInformation.put(SCIM2CommonConstants.NEW_MEMBERS, newUsers);
                }
                if (CollectionUtils.isNotEmpty(deletedUsers)) {
                    additionalInformation.put(SCIM2CommonConstants.DELETED_MEMBERS, deletedUsers);
                }

                if (StringUtils.isNotEmpty(oldGroupName)) {
                    // For PATCH operation, only patch displayName when role name has changed.
                    // Members are handled separately on the client side.
                    List<PatchOperation> patchOperations = new ArrayList<>();
                    patchOperations.add(SCIM2ConnectorUtil.createDisplayNamePatchOperation(groupName));

                    additionalInformation.put(SCIM2CommonConstants.PATCH_OPERATIONS, patchOperations);
                    additionalInformation.put(SCIM2CommonConstants.IS_ROLE_NAME_CHANGED_ON_UPDATE, true);
                    additionalInformation.put(SCIM2CommonConstants.OLD_GROUP_NAME, oldGroupName);

                    scimProvisioningClient = new ProvisioningClient(scimProvider, group,
                            additionalInformation);
                } else {
                    scimProvisioningClient = new ProvisioningClient(scimProvider, group,
                            CollectionUtils.isNotEmpty(newUsers) || CollectionUtils.isNotEmpty(deletedUsers)
                                ? additionalInformation : null);
                }
                scimProvisioningClient.provisionPatchGroup();

            } else if (ProvisioningOperation.PUT.equals(provisioningOperation)) {
                if (StringUtils.isEmpty(oldGroupName)) {
                    scimProvisioningClient = new ProvisioningClient(scimProvider, group, null);
                } else {
                    Map<String, Object> additionalInformation = new HashMap();
                    additionalInformation.put(SCIM2CommonConstants.IS_ROLE_NAME_CHANGED_ON_UPDATE, true);
                    additionalInformation.put(SCIM2CommonConstants.OLD_GROUP_NAME, oldGroupName);
                    scimProvisioningClient = new ProvisioningClient(scimProvider, group, additionalInformation);
                }
                scimProvisioningClient.provisionUpdateGroup();
            }
        } catch (Exception e) {
            String groupDisplayName = oldGroupName != null ? oldGroupName : groupName;
            throw new IdentityProvisioningException("Error while updating group : " + groupDisplayName, e);
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
