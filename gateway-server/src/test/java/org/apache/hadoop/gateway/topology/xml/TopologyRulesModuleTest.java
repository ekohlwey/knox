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
package org.apache.hadoop.gateway.topology.xml;

import org.apache.commons.digester3.Digester;
import org.apache.commons.digester3.binder.DigesterLoader;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Service;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.hadoop.gateway.topology.builder.TopologyBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;

import static org.apache.commons.digester3.binder.DigesterLoader.newLoader;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class TopologyRulesModuleTest {

  private static DigesterLoader loader;

  @Before
  public void setUp() throws Exception {
    loader = newLoader( new KnoxFormatXmlTopologyRules(), new AmbariFormatXmlTopologyRules() );
  }

  @After
  public void tearDown() throws Exception {
  }

  @Test
  public void testParseSimpleTopologyXmlInKnoxFormat() throws IOException, SAXException, URISyntaxException {
    Digester digester = loader.newDigester();
    String name = "org/apache/hadoop/gateway/topology/xml/simple-topology-knox-format.xml";
    URL url = ClassLoader.getSystemResource( name );
    assertThat( "Failed to find URL for resource " + name, url, notNullValue() );
    File file = new File( url.getFile() );
    TopologyBuilder topologyBuilder = digester.parse( url );
    Topology topology = topologyBuilder.build();
    assertThat( "Failed to parse resource " + name, topology, notNullValue() );
    topology.setTimestamp( file.lastModified() );

    assertThat( topology.getName(), is( "topology" ) );
    assertThat( topology.getTimestamp(), is( file.lastModified() ) );
    assertThat( topology.getServices().size(), is( 1 ) );

    Service comp = topology.getServices().iterator().next();
    assertThat( comp, notNullValue() );
    assertThat( comp.getRole(), is( "WEBHDFS" ) );
    assertThat( comp.getUrl(), is( "http://host:80/webhdfs/v1" ) );

    Provider provider = topology.getProviders().iterator().next();
    assertThat( provider, notNullValue() );
    assertThat( provider.isEnabled(), is(true) );
    assertThat( provider.getRole(), is( "authentication" ) );
    assertThat( provider.getParams().size(), is(5));
  }

  @Test
  public void testParseSimpleTopologyXmlInHadoopFormat() throws IOException, SAXException, URISyntaxException {
    Digester digester = loader.newDigester();
    String name = "org/apache/hadoop/gateway/topology/xml/simple-topology-ambari-format.conf";
    URL url = ClassLoader.getSystemResource( name );
    assertThat( "Failed to find URL for resource " + name, url, notNullValue() );
    File file = new File( url.getFile() );
    TopologyBuilder topologyBuilder = digester.parse( url );
    Topology topology = topologyBuilder.build();
    assertThat( "Failed to parse resource " + name, topology, notNullValue() );
    topology.setTimestamp( file.lastModified() );

    assertThat( topology.getName(), is( "topology2" ) );
    assertThat( topology.getTimestamp(), is( file.lastModified() ) );
    assertThat( topology.getServices().size(), is( 4 ) );
    assertThat( topology.getProviders().size(), is( 2 ) );

    Service namenodeService = topology.getService( "WEBHDFS", null );
    assertThat( namenodeService, notNullValue() );
    assertThat( namenodeService.getRole(), is( "WEBHDFS" ) );
    assertThat( namenodeService.getName(), nullValue() );
    assertThat( namenodeService.getUrl(), is( "http://host:50070/webhdfs/v1" ) );

    Service templetonService = topology.getService( "TEMPLETON", null );
    assertThat( templetonService, notNullValue() );
    assertThat( templetonService.getRole(), is( "TEMPLETON" ) );
    assertThat( templetonService.getName(), nullValue() );
    assertThat( templetonService.getUrl(), is( "http://host:50111/templeton/v1" ) );

    Service oozieService = topology.getService( "OOZIE", null );
    assertThat( oozieService, notNullValue() );
    assertThat( oozieService.getRole(), is( "OOZIE" ) );
    assertThat( oozieService.getName(), nullValue() );
    assertThat( oozieService.getUrl(), is( "http://host:11000/oozie" ) );

    Service hiveService = topology.getService( "HIVE", null );
    assertThat( hiveService, notNullValue() );
    assertThat( hiveService.getRole(), is( "HIVE" ) );
    assertThat( hiveService.getName(), nullValue() );
    assertThat( hiveService.getUrl(), is( "http://host:10000" ) );

    Provider authenticationProvider = topology.getProvider( "authentication", "ShiroProvider" );
    assertThat( authenticationProvider, notNullValue() );
    assertThat( authenticationProvider.isEnabled(), is( true ) );
    assertThat( authenticationProvider.getRole(), is( "authentication" ) );
    assertThat( authenticationProvider.getName(), is( "ShiroProvider" ) );
    assertThat( authenticationProvider.getParams().size(), is( 5 ) );
    assertThat( authenticationProvider.getParams().get("main.ldapRealm.contextFactory.url"), is( "ldap://localhost:33389" ) );

    Provider identityAssertionProvider = topology.getProvider( "identity-assertion", "Pseudo" );
    assertThat( identityAssertionProvider, notNullValue() );
    assertThat( identityAssertionProvider.isEnabled(), is( false ) );
    assertThat( identityAssertionProvider.getRole(), is( "identity-assertion" ) );
    assertThat( identityAssertionProvider.getName(), is( "Pseudo" ) );
    assertThat( identityAssertionProvider.getParams().size(), is( 2 ) );
    assertThat( identityAssertionProvider.getParams().get("name"), is( "user.name" ) );
  }

}
