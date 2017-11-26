/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.provisioning.*;
import org.wso2.carbon.identity.provisioning.connector.scim2.util.SCIMClaimResolver;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.objects.Group;
import org.wso2.charon3.core.objects.User;
import org.wso2.charon3.core.schema.SCIMConstants;
import org.wso2.scim2.client.ProvisioningClient;
import org.wso2.scim2.client.SCIMProvider;
import org.wso2.scim2.util.SCIM2CommonConstants;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class SCIM2ProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final long serialVersionUID = -2800777564581005554L;
    private static Log log = LogFactory.getLog(SCIM2ProvisioningConnector.class);
    private SCIMProvider scimProvider;
    private String userStoreDomainName;

    @Override
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        scimProvider = new SCIMProvider();

        if (provisioningProperties != null && provisioningProperties.length > 0) {

            for (Property property : provisioningProperties) {

                if (SCIMProvisioningConnectorConstants.SCIM_USER_EP.equals(property.getName())) {
                    populateSCIMProvider(property, SCIM2CommonConstants.ELEMENT_NAME_USER_ENDPOINT);
                } else if (SCIMProvisioningConnectorConstants.SCIM_GROUP_EP.equals(property.getName())) {
                    populateSCIMProvider(property, SCIM2CommonConstants.ELEMENT_NAME_GROUP_ENDPOINT);
                } else if (SCIMProvisioningConnectorConstants.SCIM_USERNAME.equals(property.getName())) {
                    populateSCIMProvider(property, SCIMConstants.UserSchemaConstants.USER_NAME);
                } else if (SCIMProvisioningConnectorConstants.SCIM_PASSWORD.equals(property.getName())) {
                    populateSCIMProvider(property, SCIMConstants.UserSchemaConstants.PASSWORD);
                } else if (SCIMProvisioningConnectorConstants.SCIM_USERSTORE_DOMAIN.equals(property.getName())) {
                    userStoreDomainName = property.getValue() != null ? property.getValue()
                            : property.getDefaultValue();
                } else if (SCIMProvisioningConnectorConstants.SCIM_ENABLE_PASSWORD_PROVISIONING.equals(property.getName())) {
                    populateSCIMProvider(property, SCIMProvisioningConnectorConstants.SCIM_ENABLE_PASSWORD_PROVISIONING);
                } else if (SCIMProvisioningConnectorConstants.SCIM_DEFAULT_PASSWORD.equals(property.getName())) {
                    populateSCIMProvider(property, SCIMProvisioningConnectorConstants.SCIM_DEFAULT_PASSWORD);
                }

                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property
                        .getName()) && "1".equals(property.getValue())) {
                    jitProvisioningEnabled = true;
                }
            }
        }
    }

    @Override
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity)
            throws IdentityProvisioningException {

        if (provisioningEntity != null) {

            if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                log.debug("JIT provisioning disabled for SCIM 2.0 connector");
                return null;
            }

            if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    createUser(provisioningEntity);
                } else if(provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteUser(provisioningEntity);
                }  else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                    updateUser(provisioningEntity, ProvisioningOperation.PUT);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PATCH) {
                    updateUser(provisioningEntity, ProvisioningOperation.PATCH);
                } else {
                    log.warn("Unsupported provisioning operation.");
                }
            } else if (provisioningEntity.getEntityType() == ProvisioningEntityType.GROUP) {
                if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteGroup(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    createGroup(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                    updateGroup(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PATCH) {
                    updateGroup(provisioningEntity);
                }else {
                    log.warn("Unsupported provisioning operation.");
                }
            } else {
                log.warn("Unsupported provisioning entity.");
            }
        }

        return null;

    }

    /**
     * @param userEntity
     * @throws UserStoreException
     */
    private void createUser(ProvisioningEntity userEntity) throws IdentityProvisioningException {

        try {

            List<String> userNames = getUserNames(userEntity.getAttributes());
            String userName = null;

            if (CollectionUtils.isNotEmpty(userNames)) {
                userName = userNames.get(0);
            }

            // get single-valued claims
            Map<String, String> singleValued = getSingleValuedClaims(userEntity.getAttributes());

            // if user created through management console, claim values are not present.
            User user = (User) SCIMClaimResolver.constructSCIMObjectFromAttributes(singleValued,
                    1);

            user.setUserName(userName);
            setUserPassword(user, userEntity);

            ProvisioningClient scimProvsioningClient = new ProvisioningClient(scimProvider, user,
                    null);
            scimProvsioningClient.provisionCreateUser();

        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while creating the user", e);
        }
    }

    /**
     * @param userEntity
     * @throws IdentityProvisioningException
     */
    private void deleteUser(ProvisioningEntity userEntity) throws IdentityProvisioningException {

        try {
            List<String> userNames = getUserNames(userEntity.getAttributes());
            String userName = null;

            if (CollectionUtils.isNotEmpty(userNames)) {
                userName = userNames.get(0);
            }

            User user = new User();
            user.setUserName(userName);
            ProvisioningClient scimProvsioningClient = new ProvisioningClient(scimProvider, user,
                  null);
            scimProvsioningClient.provisionDeleteUser();

        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while deleting user.", e);
        }
    }

    /**
     * @param userEntity
     * @throws IdentityProvisioningException
     */
    private void updateUser(ProvisioningEntity userEntity, ProvisioningOperation provisioningOperation) throws
            IdentityProvisioningException {

        try {

            List<String> userNames = getUserNames(userEntity.getAttributes());
            String userName = null;

            if (CollectionUtils.isNotEmpty(userNames)) {
                userName = userNames.get(0);
            }

            User user;

            // get single-valued claims
            Map<String, String> singleValued = getSingleValuedClaims(userEntity.getAttributes());

            // if user created through management console, claim values are not present.
            if (MapUtils.isNotEmpty(singleValued)) {
                user = (User) SCIMClaimResolver.constructSCIMObjectFromAttributes(singleValued,
                        1);
            } else {
                user = new User();
            }

            user.setUserName(userName);
            setUserPassword(user, userEntity);

            ProvisioningClient scimProvisioningClient = new ProvisioningClient(scimProvider, user,
                    null);
            if (ProvisioningOperation.PUT.equals(provisioningOperation)) {
                scimProvisioningClient.provisionUpdateUser();
            } else if (ProvisioningOperation.PATCH.equals(provisioningOperation)) {
                //scimProvisioningClient.provisionPatchUser();
            }
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while creating the user", e);
        }
    }

    /**
     * @param groupEntity
     * @return
     * @throws IdentityProvisioningException
     */
    private String createGroup(ProvisioningEntity groupEntity) throws IdentityProvisioningException {
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

            ProvisioningClient scimProvsioningClient = new ProvisioningClient(scimProvider, group,
                    null);
            scimProvsioningClient.provisionCreateGroup();
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while adding group.", e);
        }

        return null;
    }

    /**
     * @param groupEntity
     * @throws IdentityProvisioningException
     */
    private void deleteGroup(ProvisioningEntity groupEntity) throws IdentityProvisioningException {
        try {

            List<String> groupNames = getGroupNames(groupEntity.getAttributes());
            String groupName = null;

            if (CollectionUtils.isNotEmpty(groupNames)) {
                groupName = groupNames.get(0);
            }

            Group group = new Group();
            group.setDisplayName(groupName);

            ProvisioningClient scimProvsioningClient = new ProvisioningClient(scimProvider, group,
                    null);
            scimProvsioningClient.provisionDeleteGroup();

        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while deleting group.", e);
        }
    }

    /**
     * @param groupEntity
     * @throws IdentityProvisioningException
     */
    private void updateGroup(ProvisioningEntity groupEntity) throws IdentityProvisioningException {
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

            String oldGroupName = ProvisioningUtil.getAttributeValue(groupEntity,
                    IdentityProvisioningConstants.OLD_GROUP_NAME_CLAIM_URI);
            ProvisioningClient scimProvsioningClient = null;
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
            }else if(ProvisioningOperation.PATCH.equals(groupEntity.getOperation())){
                //scimProvsioningClient.provisionPatchGroup();
            }
        } catch (Exception e) {
            throw new IdentityProvisioningException("Error while updating group.", e);
        }
    }

    /**
     * @param property
     * @param scimPropertyName
     * @throws IdentityProvisioningException
     */
    private void populateSCIMProvider(Property property, String scimPropertyName)
            throws IdentityProvisioningException {

        if (property.getValue() != null && property.getValue().length() > 0) {
            scimProvider.setProperty(scimPropertyName, property.getValue());
        } else if (property.getDefaultValue() != null) {
            scimProvider.setProperty(scimPropertyName, property.getDefaultValue());
        }
    }

    @Override
    public String getClaimDialectUri() throws IdentityProvisioningException {
        return SCIMProvisioningConnectorConstants.DEFAULT_SCIM_DIALECT;
    }

    private void setUserPassword(User user, ProvisioningEntity userEntity) throws CharonException {
        if ("true".equals(scimProvider.getProperty(SCIMProvisioningConnectorConstants.SCIM_ENABLE_PASSWORD_PROVISIONING))) {
            user.setPassword(getPassword(userEntity.getAttributes()));
        } else if (StringUtils.isNotBlank(scimProvider.getProperty(SCIMProvisioningConnectorConstants.SCIM_DEFAULT_PASSWORD))) {
            user.setPassword(scimProvider.getProperty(SCIMProvisioningConnectorConstants.SCIM_DEFAULT_PASSWORD));
        }
    }

    public void setGroupMembers(Group group, List<String> userList) {

        if (CollectionUtils.isNotEmpty(userList)) {
            for (Iterator<String> iterator = userList.iterator(); iterator.hasNext(); ) {
                String userName = iterator.next();
                Map<String, Object> members = new HashMap<>();
                members.put(SCIMConstants.CommonSchemaConstants.DISPLAY, userName);
                group.setMember(members);
            }
        }
    }

    @Override
    protected String getUserStoreDomainName() {
        return userStoreDomainName;
    }

}
