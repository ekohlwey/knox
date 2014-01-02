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

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import org.apache.hadoop.gateway.GatewayServer;
import org.apache.hadoop.gateway.services.GatewayServices;
import org.apache.hadoop.gateway.services.security.AliasService;
import org.apache.shiro.realm.ldap.JndiLdapContextFactory;

/**
 * An extension of {@link JndiLdapContextFactory} that allows a different authentication mechanism
 * for system-level authentications (as used by authorization lookups, for example)
 * compared to regular authentication.
 * 
 * <p>
 * See {@link IsisLdapRealm} for typical configuration within <tt>shiro.ini</tt>.
 */
public class KnoxLdapContextFactory extends JndiLdapContextFactory {

    private String systemAuthenticationMechanism = "simple";
    private String clusterName = "";

    public KnoxLdapContextFactory() {
      setAuthenticationMechanism("simple");
    }
    
    @SuppressWarnings({ "unchecked", "rawtypes" })
    @Override
    protected LdapContext createLdapContext(Hashtable env) throws NamingException {
        if(getSystemUsername() != null && getSystemUsername().equals(env.get(Context.SECURITY_PRINCIPAL))) {
            env.put(Context.SECURITY_AUTHENTICATION, getSystemAuthenticationMechanism());
        }
        return super.createLdapContext(env);
    }

    public String getSystemAuthenticationMechanism() {
        return systemAuthenticationMechanism != null? systemAuthenticationMechanism: getAuthenticationMechanism();
    }
    
    public void setSystemAuthenticationMechanism(String systemAuthenticationMechanism) {
        this.systemAuthenticationMechanism = systemAuthenticationMechanism;
    }
    
    @Override
    public void setSystemPassword(String systemPass) {
      
      if ( systemPass == null ) {
        return;
      }
      
      systemPass = systemPass.trim();
      if (systemPass.length() == 0) {
        return;
      }
      
      if (!systemPass.startsWith("S{ALIAS=")) {
        super.setSystemPassword( systemPass );
        return;
      }
      
      systemPass= systemPass.substring( "S{ALIAS=".length(), systemPass.length() - 1 );
      String aliasName = systemPass;
      
      GatewayServices services = GatewayServer.getGatewayServices();
      AliasService aliasService = (AliasService)services.getService(GatewayServices.ALIAS_SERVICE);
      
      String clusterName = getClusterName();
      String systemPassword = System.getProperty(clusterName + "." + aliasName);
      if (systemPassword != null) {
        super.setSystemPassword( systemPassword );
        aliasService.addAliasForCluster(clusterName, aliasName, systemPassword);
      } else {
        char[] password = aliasService.getPasswordFromAliasForCluster(clusterName, systemPass);
        if ( password != null ) {
          super.setSystemPassword( new String(password) );
        } else {
          super.setSystemPassword( new String(systemPass) );
        }
      }
      
    }
    
    public String getClusterName() {
      return clusterName;
    }

    public void setClusterName(String clusterName) {
      if (clusterName != null) {
        this.clusterName = clusterName.trim();
      }
    }
    
}