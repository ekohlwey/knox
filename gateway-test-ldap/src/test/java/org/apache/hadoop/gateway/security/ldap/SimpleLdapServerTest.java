/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.hadoop.gateway.security.ldap;

import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;

import static org.junit.Assert.fail;

public class SimpleLdapServerTest {

  private static int port;
  private static File ldifFile;
  private static SimpleLdapDirectoryServer ldap;

  @BeforeClass
  public static void setup() throws Exception {
    port = findFreePort();
    ldifFile = new File( ClassLoader.getSystemResource( "users.ldif" ).toURI() );
    ldap = new SimpleLdapDirectoryServer( "dc=hadoop,dc=apache,dc=org", ldifFile, new Transport[]{ new TcpTransport( port ) } );
    ldap.start();
  }

  @AfterClass
  public static void cleanup() throws Exception {
    if( ldap != null ) {
      ldap.stop( true );
    }
  }

  private static int findFreePort() throws IOException {
    ServerSocket socket = new ServerSocket(0);
    int port = socket.getLocalPort();
    socket.close();
    return port;
  }

  @Test
  public void test() throws LdapException, IOException {
    LdapConnection connection = new LdapNetworkConnection( "localhost", port );

    connection.bind( "uid=guest,ou=people,dc=hadoop,dc=apache,dc=org", "guest-password" );

    try {
      connection.bind( "uid=nobody,ou=people,dc=hadoop,dc=apache,dc=org", "guest-password" );
      fail( "Expected LdapAuthenticatinoException" );
    } catch ( LdapAuthenticationException e ) {
      // Expected
    }

    try {
      connection.bind( "uid=guest,ou=people,dc=hadoop,dc=apache,dc=org", "wrong-password" );
      fail( "Expected LdapAuthenticatinoException" );
    } catch ( LdapAuthenticationException e ) {
      // Expected
    }

    connection.close();
  }

}