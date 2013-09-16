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
package org.apache.hadoop.gateway.securequery;

import org.apache.hadoop.gateway.filter.rewrite.api.UrlRewriteEnvironment;
import org.apache.hadoop.gateway.filter.rewrite.spi.UrlRewriteContext;
import org.apache.hadoop.gateway.services.GatewayServices;
import org.apache.hadoop.gateway.services.security.AliasService;
import org.apache.hadoop.gateway.services.security.CryptoService;
import org.apache.hadoop.gateway.services.security.impl.DefaultCryptoService;
import org.apache.hadoop.gateway.util.urltemplate.Params;
import org.apache.hadoop.gateway.util.urltemplate.Parser;
import org.apache.hadoop.gateway.util.urltemplate.Query;
import org.apache.hadoop.gateway.util.urltemplate.Template;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Test;

import java.util.Arrays;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.nullValue;

public class SecureQueryEncryptDecryptProcessorTest {

  @Test
  public void testEncryptDecrypt() throws Exception {
    Query query;
    Template origTemplate = Parser.parse( "http://host:0/path/file?query-param-name=query-param-value" );

    // Test encryption.  Results are left in encTemplate

    AliasService as = EasyMock.createNiceMock( AliasService.class );
    String secret = "sdkjfhsdkjfhsdfs";
    EasyMock.expect( as.getPasswordFromAliasForCluster("test-cluster-name", "encryptQueryString")).andReturn( secret.toCharArray() ).anyTimes();
    CryptoService cryptoService = new DefaultCryptoService();
    ((DefaultCryptoService)cryptoService).setAliasService(as);
    GatewayServices gatewayServices = EasyMock.createNiceMock( GatewayServices.class );
    EasyMock.expect( gatewayServices.getService( GatewayServices.CRYPTO_SERVICE ) ).andReturn( cryptoService );

    UrlRewriteEnvironment encEnvironment = EasyMock.createNiceMock( UrlRewriteEnvironment.class );
    EasyMock.expect( encEnvironment.getAttribute( GatewayServices.GATEWAY_SERVICES_ATTRIBUTE ) ).andReturn( gatewayServices ).anyTimes();    
    EasyMock.expect( encEnvironment.resolve( "cluster.name" ) ).andReturn( Arrays.asList( "test-cluster-name" ) ).anyTimes();
    UrlRewriteContext encContext = EasyMock.createNiceMock( UrlRewriteContext.class );
    EasyMock.expect( encContext.getCurrentUrl() ).andReturn( origTemplate );
    Capture<Template> encTemplate = new Capture<Template>();
    encContext.setCurrentUrl( EasyMock.capture( encTemplate ) );
    EasyMock.replay( gatewayServices, as, encEnvironment, encContext );

    SecureQueryEncryptDescriptor descriptor = new SecureQueryEncryptDescriptor();
    SecureQueryEncryptProcessor processor = new SecureQueryEncryptProcessor();
    processor.initialize( encEnvironment, descriptor );
    processor.process( encContext );

    assertThat( encTemplate, notNullValue() );
    query = encTemplate.getValue().getQuery().get( "_" );
    assertThat( query.getFirstValue().getPattern().length(), greaterThan( 1 ) );
    query = encTemplate.getValue().getQuery().get( "query-param-name" );
    assertThat( query, nullValue() );

    // Test decryption.  Results are left in decTemplate.

    gatewayServices = EasyMock.createNiceMock( GatewayServices.class );
    EasyMock.expect( gatewayServices.getService( GatewayServices.CRYPTO_SERVICE ) ).andReturn( cryptoService );
    as = EasyMock.createNiceMock( AliasService.class );
    EasyMock.expect( as.getPasswordFromAliasForCluster("test-cluster-name", "encryptQueryString")).andReturn( secret.toCharArray() ).anyTimes();

    UrlRewriteEnvironment decEnvironment = EasyMock.createNiceMock( UrlRewriteEnvironment.class );
    EasyMock.expect( decEnvironment.getAttribute( GatewayServices.GATEWAY_SERVICES_ATTRIBUTE ) ).andReturn( gatewayServices ).anyTimes();    
    EasyMock.expect( decEnvironment.resolve( "cluster.name" ) ).andReturn( Arrays.asList( "test-cluster-name" ) ).anyTimes();
    Params decParams = EasyMock.createNiceMock( Params.class );
    EasyMock.expect( decParams.resolve( "cluster.name" ) ).andReturn( Arrays.asList("test-cluster-name") ).anyTimes();
    UrlRewriteContext decContext = EasyMock.createNiceMock( UrlRewriteContext.class );
    EasyMock.expect( decContext.getCurrentUrl() ).andReturn( encTemplate.getValue() );
    EasyMock.expect( decContext.getParameters() ).andReturn( decParams );
    Capture<Template> decTemplate = new Capture<Template>();
    decContext.setCurrentUrl( EasyMock.capture( decTemplate ) );
    EasyMock.replay( gatewayServices, as, decEnvironment, decParams, decContext );

    SecureQueryDecryptDescriptor descriptor1 = new SecureQueryDecryptDescriptor();
    SecureQueryDecryptProcessor decProcessor = new SecureQueryDecryptProcessor();
    decProcessor.initialize( decEnvironment, descriptor1 );
    decProcessor.process( decContext );

    assertThat( decTemplate, notNullValue() );
    assertThat( decTemplate.getValue(), notNullValue() );
    query = decTemplate.getValue().getQuery().get( "query-param-name" );
    assertThat( query.getFirstValue().getPattern(), is( "query-param-value" ) );
    query = decTemplate.getValue().getQuery().get( "_" );
    assertThat( query, nullValue() );
  }

}
