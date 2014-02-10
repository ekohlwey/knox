/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.apache.hadoop.gateway.shirorealm;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.naming.AuthenticationException;
import javax.naming.InvalidNameException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;

import org.apache.hadoop.gateway.GatewayMessages;
import org.apache.hadoop.gateway.i18n.messages.MessagesFactory;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.ldap.JndiLdapRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.StringUtils;

/**
 * Implementation of {@link org.apache.shiro.realm.ldap.JndiLdapRealm} that also
 * returns each user's groups.
 * This implementation is heavily based on org.apache.isis.security.shiro.IsisLdapRealm.
 * 
 * This implementation saves looked up ldap groups in Shiro Session to make them
 * easy to be looked up outside of this object
 * 
 * <p>
 * Sample config for <tt>shiro.ini</tt>:
 * 
 * [main]
 * ldapRealm=org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm
 * ldapGroupContextFactory=org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory
 * ldapRealm.contextFactory=$ldapGroupContextFactory
 * ldapRealm.contextFactory.authenticationMechanism=simple
 * ldapRealm.contextFactory.url=ldap://localhost:33389
 * ldapRealm.userDnTemplate=uid={0},ou=people,dc=hadoop,dc=apache,dc=org
 * ldapRealm.authorizationEnabled=true
 * ldapRealm.contextFactory.systemAuthenticationMechanism=simple
 * ldapRealm.searchBase=ou=groups,dc=hadoop,dc=apache,dc=org
 * ldapRealm.groupObjectClass=groupofnames
 * ldapRealm.memberAttribute=member
 * ldapRealm.memberAttributeValueTemplate=cn={0},ou=people,dc=hadoop,dc=apache,dc=org
 * ldapRealm.contextFactory.systemUsername=uid=guest,ou=people,dc=hadoop,dc=apache,dc=org
 * ldapRealm.contextFactory.clusterName=sandbox
 * ldapRealm.contextFactory.systemPassword=S{ALIAS=ldcSystemPassword}
 * [urls]
 * **=authcBasic
 *
 * # optional mapping from physical groups to logical application roles
 * ldapRealm.rolesByGroup = \
 *    LDN_USERS: user_role,\
 *    NYK_USERS: user_role,\
 *    HKG_USERS: user_role,\
 *    GLOBAL_ADMIN: admin_role,\
 *    DEMOS: self-install_role
 * 
 * ldapRealm.permissionsByRole=\
 *    user_role = *:ToDoItemsJdo:*:*,\
 *                *:ToDoItem:*:*; \
 *    self-install_role = *:ToDoItemsFixturesService:install:* ; \
 *    admin_role = *
 * 
 * securityManager.realms = $ldapRealm
 * 
 * </pre>
 */
public class KnoxLdapRealm extends JndiLdapRealm {

    private static GatewayMessages LOG = MessagesFactory.get( GatewayMessages.class );
  
    private static final String MEMBER_SUBSTITUTION_TOKEN = "{0}";
    private final static SearchControls SUBTREE_SCOPE = new SearchControls();
    private final static SearchControls ONELEVEL_SCOPE = new SearchControls();
    
    private final static String  SUBJECT_USER_ROLES = "subject.userRoles";
    private final static String  SUBJECT_USER_GROUPS = "subject.userGroups";

    private final static String  MEMBER_URL = "memberUrl";
   
    static {
        SUBTREE_SCOPE.setSearchScope(SearchControls.SUBTREE_SCOPE);
        ONELEVEL_SCOPE.setSearchScope(SearchControls.ONELEVEL_SCOPE);
    }
    
    private String searchBase;
    // typical alue: groupOfNames, groupOfUniqueNames, groupOfUrls
    private String groupObjectClass = "groupOfNames";
    
    //  typical value: member, uniqueMember, meberUrl
    private String memberAttribute = "member";

    private String groupIdAttribute = "cn";
    
    private String memberAttributeValuePrefix = "uid={0}";
    private String memberAttributeValueSuffix = "";
    
    private final Map<String,String> rolesByGroup = new LinkedHashMap<String, String>();
    private final Map<String,List<String>> permissionsByRole = new LinkedHashMap<String, List<String>>();
    
    private boolean authorizationEnabled;

    public KnoxLdapRealm() {
    }
    
    /**
     * Get groups from LDAP.
     * 
     * @param principals
     *            the principals of the Subject whose AuthenticationInfo should
     *            be queried from the LDAP server.
     * @param ldapContextFactory
     *            factory used to retrieve LDAP connections.
     * @return an {@link AuthorizationInfo} instance containing information
     *         retrieved from the LDAP server.
     * @throws NamingException
     *             if any LDAP errors occur during the search.
     */
    @Override
    protected AuthorizationInfo queryForAuthorizationInfo(final PrincipalCollection principals, 
        final LdapContextFactory ldapContextFactory) throws NamingException {
      if (!isAuthorizationEnabled()) {
        return null;
      }
      final Set<String> roleNames = getRoles(principals, ldapContextFactory);
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo(roleNames);
        Set<String> stringPermissions = permsFor(roleNames);
        simpleAuthorizationInfo.setStringPermissions(stringPermissions);
        return simpleAuthorizationInfo;
    }

    private Set<String> getRoles(final PrincipalCollection principals, 
        final LdapContextFactory ldapContextFactory) throws NamingException {
        final String username = (String) getAvailablePrincipal(principals);

        LdapContext systemLdapCtx = null;
        try {
            systemLdapCtx = ldapContextFactory.getSystemLdapContext();
            return rolesFor(username, systemLdapCtx, ldapContextFactory);
        } catch (AuthenticationException e) {
          LOG.failedToGetSystemLdapConnection(e);
          return Collections.emptySet();
        } finally {
            LdapUtils.closeContext(systemLdapCtx);
        }
    }

    private Set<String> rolesFor(final String userName, final LdapContext ldapCtx, 
        final LdapContextFactory ldapContextFactory) throws NamingException {
        final Set<String> roleNames = new HashSet();
        final Set<String> groupNames = new HashSet();
        
        // ldapsearch -h localhost -p 33389 -D uid=guest,ou=people,dc=hadoop,dc=apache,dc=org -w  guest-password 
        //       -b dc=hadoop,dc=apache,dc=org -s sub '(objectclass=*)'
        final NamingEnumeration<SearchResult> searchResultEnum = ldapCtx.search(searchBase, "objectClass="+groupObjectClass, SUBTREE_SCOPE);
        
        while (searchResultEnum.hasMore()) { // searchResults contains all the groups in search scope
            final SearchResult group = searchResultEnum.next();
            addRoleIfMember(userName, group, roleNames, groupNames, ldapContextFactory);
        }
        
        // save role names and group names in session so that they can be easily looked up outside of this object
        SecurityUtils.getSubject().getSession().setAttribute(SUBJECT_USER_ROLES, roleNames);
        SecurityUtils.getSubject().getSession().setAttribute(SUBJECT_USER_GROUPS, groupNames);
        
        return roleNames;
    }

  private void addRoleIfMember(final String userName, final SearchResult group,
      final Set<String> roleNames, final Set<String> groupNames,
      final LdapContextFactory ldapContextFactory) throws NamingException {
   
    String userDn = memberAttributeValuePrefix + userName + memberAttributeValueSuffix;
    Attribute attribute = group.getAttributes().get(getGroupIdAttribute()); 
    String groupName = attribute.get().toString();
    
    final NamingEnumeration<? extends Attribute> attributeEnum = group
        .getAttributes().getAll();
    while (attributeEnum.hasMore()) {
      final Attribute attr = attributeEnum.next();
      if (!memberAttribute.equalsIgnoreCase(attr.getID())) {
        continue;
      }
      final NamingEnumeration<?> e = attr.getAll();
      while (e.hasMore()) {
        String attrValue = e.next().toString();
        if (memberAttribute.equalsIgnoreCase(MEMBER_URL)) {
          boolean dynamicGroupMember = isUserMemberOfDynamicGroup(userDn, 
              attrValue, // memberUrl value
              ldapContextFactory);
          if (dynamicGroupMember) {
            groupNames.add(groupName);
            String roleName = roleNameFor(groupName);
            if (roleName != null) {
              roleNames.add(roleName);
            } else {
              roleNames.add(groupName);
            }
          }
        } else {
          if (userDn.equals(attrValue)) {
         
            groupNames.add(groupName);
            String roleName = roleNameFor(groupName);
            if (roleName != null) {
              roleNames.add(roleName);
            } else {
              roleNames.add(groupName);
            }
            break;
          }
        }
      }

    }
  }

    private String roleNameFor(String groupName) {
        return !rolesByGroup.isEmpty() ? rolesByGroup.get(groupName) : groupName;
    }


    private Set<String> permsFor(Set<String> roleNames) {
        Set<String> perms = new LinkedHashSet<String>(); // preserve order
        for(String role: roleNames) {
            List<String> permsForRole = permissionsByRole.get(role);
            if(permsForRole != null) {
                perms.addAll(permsForRole);
            }
        }
        return perms;
    }

    public String getSearchBase() {
        return searchBase;
    }

    public void setSearchBase(String searchBase) {
      this.searchBase = searchBase;
    }
    
    public String getGroupObjectClass() {
      return groupObjectClass;
    }
    
    public void setGroupObjectClass(String groupObjectClassAttribute) {
        this.groupObjectClass = groupObjectClassAttribute;
    }

    public String getMemberAttribute() {
      return memberAttribute;
    }
    
    public void setMemberAttribute(String memberAttribute) {
        this.memberAttribute = memberAttribute;
    }
    
    public String getGroupIdAttribute() {
      return groupIdAttribute;
    }
    
    public void setGroupIdAttribute(String memberAttribute) {
        this.groupIdAttribute = groupIdAttribute;
    }
    
    public void setMemberAttributeValueTemplate(String template) {
        if (!StringUtils.hasText(template)) {
            String msg = "User DN template cannot be null or empty.";
            throw new IllegalArgumentException(msg);
        }
        int index = template.indexOf(MEMBER_SUBSTITUTION_TOKEN);
        if (index < 0) {
            String msg = "Member attribute value template must contain the '" +
                    MEMBER_SUBSTITUTION_TOKEN + "' replacement token to understand how to " +
                    "parse the group members.";
            throw new IllegalArgumentException(msg);
        }
        String prefix = template.substring(0, index);
        String suffix = template.substring(prefix.length() + MEMBER_SUBSTITUTION_TOKEN.length());
        this.memberAttributeValuePrefix = prefix;
        this.memberAttributeValueSuffix = suffix;
    }

    public void setRolesByGroup(Map<String, String> rolesByGroup) {
        this.rolesByGroup.putAll(rolesByGroup);
    }

    public void setPermissionsByRole(String permissionsByRoleStr) {
        permissionsByRole.putAll(parsePermissionByRoleString(permissionsByRoleStr));
    }
    
    public boolean isAuthorizationEnabled() {
      return authorizationEnabled;
    }

    public void setAuthorizationEnabled(boolean authorizationEnabled) {
      this.authorizationEnabled = authorizationEnabled;
    }
    
    private Map<String, List<String>> parsePermissionByRoleString(String permissionsByRoleStr) {
      Map<String,List<String>> perms = new HashMap<String, List<String>>();
   
      // split by semicolon ; then by eq = then by  comma ,
      StringTokenizer stSem = new StringTokenizer(permissionsByRoleStr, ";");
      while (stSem.hasMoreTokens()) {
        String roleAndPerm = stSem.nextToken();
        StringTokenizer stEq = new StringTokenizer(roleAndPerm, "=");
        if (stEq.countTokens() != 2) {
          continue;
        }
        String role = stEq.nextToken().trim();
        String perm = stEq.nextToken().trim();
        StringTokenizer stCom = new StringTokenizer(perm, ",");
        List<String> permList = new ArrayList<String>();
        while (stCom.hasMoreTokens()) {
          permList.add(stCom.nextToken().trim());
        }
        perms.put(role,  permList);
      }
      return perms;
  }

  boolean isUserMemberOfDynamicGroup(String userDnString, String memberUrl,
      final LdapContextFactory ldapContextFactory) throws NamingException {

    // ldap://host:port/dn?attributes?scope?filter?extensions

    boolean member = false;

    if (memberUrl == null) {
      return false;
    }
    String[] tokens = memberUrl.split("\\?");
    if (tokens.length < 4) {
      return false;
    }

    String searchBaseString = tokens[0]
        .substring(tokens[0].lastIndexOf("/") + 1);
    String searchScope = tokens[2];
    String searchFilter = tokens[3];

    LdapName searchBaseDn = new LdapName(searchBaseString);
    LdapName userDn = new LdapName(userDnString);
    // do scope test
    if (searchScope.equalsIgnoreCase("base")) {
      return false;
    }
    if (!userDn.toString().endsWith(searchBaseDn.toString())) {
      return false;
    }
    if (searchScope.equalsIgnoreCase("one")
        && (userDn.size() != searchBaseDn.size() - 1)) {
      return false;
    }
    // search for the filter, substituting base with userDn
    // search for base_dn=userDn, scope=base, filter=filter
    LdapContext systemLdapCtx = null;
    systemLdapCtx = ldapContextFactory.getSystemLdapContext();
    final NamingEnumeration<SearchResult> searchResultEnum = systemLdapCtx
        .search(userDn, searchFilter,
            searchScope.equalsIgnoreCase("sub") ? SUBTREE_SCOPE
                : ONELEVEL_SCOPE);
    if (searchResultEnum.hasMore()) {
      return true;
    }

    return member;
  }
   
}
