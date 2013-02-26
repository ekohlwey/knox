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
import org.apache.hadoop.gateway.util.urltemplate.Parser;
import org.apache.hadoop.gateway.util.urltemplate.Template;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Test;
import sun.misc.BASE64Encoder;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class SecureQueryEncodeProcessorTest {

  @Test
  public void testSimpleQueryEncoding() throws Exception {
    UrlRewriteEnvironment environment = EasyMock.createNiceMock( UrlRewriteEnvironment.class );

    Template inTemplate = Parser.parse( "http://host:0/root/path?query" );
    UrlRewriteContext context = EasyMock.createNiceMock( UrlRewriteContext.class );
    EasyMock.expect( context.getCurrentUrl() ).andReturn( inTemplate );
    Capture<Template> outTemplate = new Capture<Template>();
    context.setCurrentUrl( EasyMock.capture( outTemplate ) );

    EasyMock.replay( environment, context );

    SecureQueryEncodeDescriptor descriptor = new SecureQueryEncodeDescriptor();
    SecureQueryEncodeProcessor processor = new SecureQueryEncodeProcessor();
    processor.initialize( environment, descriptor );
    processor.process( context );

    BASE64Encoder encoder = new BASE64Encoder();
    String encQuery = encoder.encode( "query".getBytes("utf-8" ) );
    encQuery = encQuery.replaceAll( "\\=", "" );
    String outExpect = "http://host:0/root/path?_=" + encQuery;
    String outActual = outTemplate.getValue().toString();
    assertThat( outActual, is( outExpect ) );
  }

}
