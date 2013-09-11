/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.gateway.filter;

import javax.security.auth.Subject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.hadoop.gateway.i18n.messages.MessagesFactory;
import org.apache.hadoop.gateway.security.GroupPrincipal;
import org.apache.hadoop.gateway.security.ImpersonatedPrincipal;
import org.apache.hadoop.gateway.security.PrimaryPrincipal;

import java.io.IOException;
import java.security.AccessController;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;

public class AclsAuthorizationFilter implements Filter {
  private static AclsAuthorizationMessages log = MessagesFactory.get( AclsAuthorizationMessages.class );

  private String resourceRole = null;
  private ArrayList<String> users;
  private ArrayList<String> groups;
  private ArrayList<String> ipaddr;
  private boolean anyUser = true;
  private boolean anyGroup = true;
  private boolean anyIP = true;
  private String aclProcessingMode = null;
  
  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    resourceRole = getInitParameter(filterConfig, "resource.role");
    log.initializingForResourceRole(resourceRole);
    aclProcessingMode = getInitParameter(filterConfig, resourceRole + ".acl.processing.mode");
    if (aclProcessingMode == null) {
      aclProcessingMode = "OR";
    }
    log.aclProcessingMode(aclProcessingMode);
    String acls = getInitParameter(filterConfig, resourceRole + ".acls");
    parseAcls(acls);
  }

  private String getInitParameter(FilterConfig filterConfig, String paramName) {
    return filterConfig.getInitParameter(paramName.toLowerCase());
  }

  private void parseAcls(String acls) {
    if (acls != null) {
      String[] parts = acls.split(";");
      if (parts.length != 3 && parts.length > 0) {
        log.invalidAclsFoundForResource(resourceRole);
        // TODO: should probably throw an exception since this can leave
        // us in an insecure state - either that or lock it down so that
        // it isn't unprotected
      }
      else {
        log.aclsFoundForResource(resourceRole);
      }
      users = new ArrayList<String>();
      Collections.addAll(users, parts[0].split(","));
      if (!users.contains("*")) {
        anyUser = false;
      }
      groups = new ArrayList<String>();
      Collections.addAll(groups, parts[1].split(","));
      if (!groups.contains("*")) {
        anyGroup = false;
      }

      ipaddr = new ArrayList<String>();
      Collections.addAll(ipaddr, parts[2].split(","));
      if (!ipaddr.contains("*")) {
        anyIP = false;
      }
    }
    else {
      log.noAclsFoundForResource(resourceRole);
      users = new ArrayList<String>();
      groups = new ArrayList<String>();
      ipaddr = new ArrayList<String>();
    }
  }

  public void destroy() {

  }

  public void doFilter(ServletRequest request, ServletResponse response,
      FilterChain chain) throws IOException, ServletException {
    boolean accessGranted = enforceAclAuthorizationPolicy(request, response, chain);
    log.accessGranted(accessGranted);

    if (accessGranted) {
      chain.doFilter(request, response);
    }
    else {
      sendUnauthorized((HttpServletResponse) response);
    }
  }

  private boolean enforceAclAuthorizationPolicy(ServletRequest request,
      ServletResponse response, FilterChain chain) {
    HttpServletRequest req = (HttpServletRequest) request;
    
    // before enforcing acls check whether there are no acls defined 
    // which would mean that there are no restrictions
    if (users.size() == 0 && groups.size() == 0 && ipaddr.size() == 0) {
      return true;
    }

    boolean userAccess = false;
    boolean groupAccess = false;
    boolean ipAddrAccess = false;
    
    Subject subject = Subject.getSubject(AccessController.getContext());
    Principal primaryPrincipal = (Principal)subject.getPrincipals(PrimaryPrincipal.class).toArray()[0];
    log.primaryPrincipal(primaryPrincipal.getName());
    Object[] impersonations = subject.getPrincipals(ImpersonatedPrincipal.class).toArray();
    if (impersonations.length > 0) {
      log.impersonatedPrincipal(((Principal)impersonations[0]).getName());
      userAccess = checkUserAcls((Principal)impersonations[0]);
      log.impersonatedPrincipalHasAccess(userAccess);
    }
    else {
      userAccess = checkUserAcls(primaryPrincipal);
      log.primaryPrincipalHasAccess(userAccess);
    }
    Object[] groups = subject.getPrincipals(GroupPrincipal.class).toArray();
    if (groups.length > 0) {
//      System.out.println("GroupPrincipal: " + ((Principal)groups[0]).getName());
      groupAccess = checkGroupAcls(groups);
      log.groupPrincipalHasAccess(groupAccess);
    }
    log.remoteIPAddress(req.getRemoteAddr());
    ipAddrAccess = checkRemoteIpAcls(req.getRemoteAddr());
    log.remoteIPAddressHasAccess(ipAddrAccess);
    
    if (aclProcessingMode.equals("OR")) {
      // need to interpret '*' as excluded for OR semantics
      // to make sense and not grant access to everyone by mistake.
      // exclusion in OR is equivalent to denied
      // so, let's set each one that contains '*' to false.
      if (anyUser) userAccess = false;
      if (anyGroup) groupAccess = false;
      if (anyIP) ipAddrAccess = false;
      
      return (userAccess || groupAccess || ipAddrAccess);
    }
    else if (aclProcessingMode.equals("AND")) {
      return (userAccess && groupAccess && ipAddrAccess);
    }
    return false;
  }

  private boolean checkRemoteIpAcls(String remoteAddr) {
    boolean allowed = false;
    if (remoteAddr == null) {
      return false;
    }
    if (anyIP) {
      allowed = true;
    }
    else {
      if (ipaddr.contains(remoteAddr)) {
        allowed = true;
      }
    }
    return allowed;
  }

  private boolean checkUserAcls(Principal user) {
    boolean allowed = false;
    if (user == null) {
      return false;
    }
    if (anyUser) {
      allowed = true;
    }
    else {
      if (users.contains(user.getName())) {
        allowed = true;
      }
    }
    return allowed;
  }

  private boolean checkGroupAcls(Object[] userGroups) {
    boolean allowed = false;
    if (userGroups == null) {
      return false;
    }
    if (anyGroup) {
      allowed = true;
    }
    else {
      for (int i = 0; i < userGroups.length; i++) {
        if (groups.contains(((Principal)userGroups[i]).getName())) {
          allowed = true;
          break;
        }
      }
    }
    return allowed;
  }

  private void sendUnauthorized(HttpServletResponse res) {
    sendErrorCode(res, 401);
  }

  private void sendErrorCode(HttpServletResponse res, int code) {
    try {
      res.sendError(code);
    } catch (IOException e) {
      // TODO: log appropriately
      e.printStackTrace();
    }
  }
}
