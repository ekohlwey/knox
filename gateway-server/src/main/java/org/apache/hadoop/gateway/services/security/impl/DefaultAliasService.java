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
package org.apache.hadoop.gateway.services.security.impl;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.apache.hadoop.gateway.GatewayMessages;
import org.apache.hadoop.gateway.config.GatewayConfig;
import org.apache.hadoop.gateway.i18n.messages.MessagesFactory;
import org.apache.hadoop.gateway.services.ServiceLifecycleException;
import org.apache.hadoop.gateway.services.security.AliasService;
import org.apache.hadoop.gateway.services.security.KeystoreService;
import org.apache.hadoop.gateway.services.security.KeystoreServiceException;

public class DefaultAliasService implements AliasService {
  private static final GatewayMessages LOG = MessagesFactory.get( GatewayMessages.class ); 

  protected char[] chars = { 'a', 'b', 'c', 'd', 'e', 'f', 'g',
  'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
  'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K',
  'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  '2', '3', '4', '5', '6', '7', '8', '9',};

  private KeystoreService keystoreService;

  @Override
  public void init(GatewayConfig config, Map<String, String> options)
      throws ServiceLifecycleException {
  }

  @Override
  public void start() throws ServiceLifecycleException {
  }

  @Override
  public void stop() throws ServiceLifecycleException {
  }
  
  /* (non-Javadoc)
   * @see org.apache.hadoop.gateway.services.security.impl.AliasService#getAliasForCluster(java.lang.String, java.lang.String)
   */
  @Override
  public char[] getPasswordFromAliasForCluster(String clusterName, String alias) {
    return getPasswordFromAliasForCluster(clusterName, alias, false);
  }

  /* (non-Javadoc)
   * @see org.apache.hadoop.gateway.services.security.impl.AliasService#getAliasForCluster(java.lang.String, java.lang.String, boolean)
   */
  @Override
  public char[] getPasswordFromAliasForCluster(String clusterName, String alias, boolean generate) {
    char[] credential = null;
    try {
      credential = keystoreService.getCredentialForCluster(clusterName, alias);
      if (credential == null) {
        if (generate) {
          generateAliasForCluster(clusterName, alias);
          credential = keystoreService.getCredentialForCluster(clusterName, alias);
        }
      }
    } catch (KeystoreServiceException e) {
      LOG.failedToGetCredentialForCluster(clusterName, e);
    }
    return credential;
  }

  private String generatePassword(int length) {
    StringBuffer sb = new StringBuffer();
    Random r = new Random();
    for (int i = 0; i < length; i++) {
      sb.append(chars[r.nextInt(chars.length)]);
    }
    return sb.toString();
  }
  
  public void setKeystoreService(KeystoreService ks) {
    this.keystoreService = ks;
  }

  @Override
  public void generateAliasForCluster(String clusterName, String alias) {
    try {
      keystoreService.getCredentialStoreForCluster(clusterName);
    } catch (KeystoreServiceException e) {
      LOG.failedToGenerateAliasForCluster(clusterName, e);
    }
    String passwordString = generatePassword(16);
    addAliasForCluster(clusterName, alias, passwordString);
  }

  /* (non-Javadoc)
   * @see org.apache.hadoop.gateway.services.security.impl.AliasService#addAliasForCluster(java.lang.String, java.lang.String, java.lang.String)
   */
  @Override
  public void addAliasForCluster(String clusterName, String alias, String value) {
    try {
      keystoreService.addCredentialForCluster(clusterName, alias, value);
    } catch (KeystoreServiceException e) {
      LOG.failedToAddCredentialForCluster(clusterName, e);
    }
  }

  @Override
  public void removeAliasForCluster(String clusterName, String alias) {
    keystoreService.removeCredentialForCluster(clusterName, alias);
  }

  @Override
  public char[] getPasswordFromAliasForGateway(String alias) {
    return getPasswordFromAliasForCluster("__gateway", alias);
  }

  @Override
  public void generateAliasForGateway(String alias) {
    generateAliasForCluster("__gateway", alias);
  }

  /* (non-Javadoc)
   * @see org.apache.hadoop.gateway.services.security.AliasService#getCertificateForGateway(java.lang.String)
   */
  @Override
  public Certificate getCertificateForGateway(String alias) {
    Certificate cert = null;
    try {
      cert = this.keystoreService.getKeystoreForGateway().getCertificate(alias);
    } catch (KeyStoreException e) {
      LOG.unableToRetrieveCertificateForGateway(e);
      // should we throw an exception?
    } catch (KeystoreServiceException e) {
      LOG.unableToRetrieveCertificateForGateway(e);
    }
    return cert;
  }

  /* (non-Javadoc)
   * @see org.apache.hadoop.gateway.services.security.AliasService#getAliasesForCluster(java.lang.String)
   */
  @Override
  public List<String> getAliasesForCluster(String clusterName) {
    ArrayList<String> list = new ArrayList<String>();
    KeyStore keyStore;
    try {
      keyStore = keystoreService.getCredentialStoreForCluster(clusterName);
      if (keyStore != null) {
        String alias = null;
        try {
          Enumeration<String> e = keyStore.aliases();
          while (e.hasMoreElements()) {
             alias = e.nextElement();
             // only include the metadata key names in the list of names
             if (!alias.contains("@")) {
                 list.add(alias);
             }
          }
        } catch (KeyStoreException e) {
          LOG.failedToGetCredentialForCluster(clusterName, e);
        }
      }
    } catch (KeystoreServiceException kse) {
      LOG.failedToGetCredentialForCluster(clusterName, kse);
    }
    return list;
  }
}
