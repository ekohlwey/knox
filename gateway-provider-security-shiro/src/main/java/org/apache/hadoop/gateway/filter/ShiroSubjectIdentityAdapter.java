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

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.apache.hadoop.gateway.security.GroupPrincipal;
import org.apache.hadoop.gateway.security.PrimaryPrincipal;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;

public class ShiroSubjectIdentityAdapter implements Filter {
  
  private static final String SUBJECT_USER_GROUPS = "subject.userGroups";

  @Override
  public void init( FilterConfig filterConfig ) throws ServletException {
  }

  public void destroy() {
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
      throws IOException, ServletException {
    
    Subject subject = SecurityUtils.getSubject();
    
    // trigger call to shiro authorization realm
    // we use shiro authorization realm to look up groups
    subject.hasRole("authenticatedUser");
    
    final String principalName = (String) subject.getPrincipal();

    CallableChain callableChain = new CallableChain(request, response, chain);
    SecurityUtils.getSubject().execute(callableChain);
  }
  
  private class CallableChain implements Callable<Void> {
    private FilterChain chain = null;
    ServletRequest request = null;
    ServletResponse response = null;
    
    CallableChain(ServletRequest request, ServletResponse response, FilterChain chain) {
      this.request = request;
      this.response = response;
      this.chain = chain;
    }

    @Override
    public Void call() throws Exception {
      PrivilegedExceptionAction<Void> action = new PrivilegedExceptionAction<Void>() {
        @Override
        public Void run() throws Exception {
          chain.doFilter( request, response );
          return null;
        }
      };
      Subject shiroSubject = SecurityUtils.getSubject();
      final String principal = (String) shiroSubject.getPrincipal();
      HashSet emptySet = new HashSet();
      Set<Principal> principals = new HashSet<Principal>();
      Principal p = new PrimaryPrincipal(principal);
      principals.add(p);
      
      // map ldap groups saved in session to Java Subject GroupPrincipal(s)
      if (SecurityUtils.getSubject().getSession().getAttribute(SUBJECT_USER_GROUPS) != null) {
        Set<String> userRoles = (Set<String>)SecurityUtils.getSubject().getSession().getAttribute(SUBJECT_USER_GROUPS);
        for (String userRole : userRoles) {
          Principal gp = new GroupPrincipal(userRole);
          principals.add(gp);
        }
      }
      
      // TODO: add groups through extended JndiLdapRealm implementation once Jira KNOX-4 is resolved
      
//      The newly constructed Sets check whether this Subject has been set read-only 
//      before permitting subsequent modifications. The newly created Sets also prevent 
//      illegal modifications by ensuring that callers have sufficient permissions.
//
//      To modify the Principals Set, the caller must have AuthPermission("modifyPrincipals"). 
//      To modify the public credential Set, the caller must have AuthPermission("modifyPublicCredentials"). 
//      To modify the private credential Set, the caller must have AuthPermission("modifyPrivateCredentials").
      javax.security.auth.Subject subject = new javax.security.auth.Subject(true, principals, emptySet, emptySet);
      javax.security.auth.Subject.doAs( subject, action );
      
      return null;
    }
    
  }

}
