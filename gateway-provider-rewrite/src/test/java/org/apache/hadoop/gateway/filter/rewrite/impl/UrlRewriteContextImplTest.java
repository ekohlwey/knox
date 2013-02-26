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
package org.apache.hadoop.gateway.filter.rewrite.impl;

import org.apache.hadoop.gateway.filter.rewrite.api.UrlRewriteEnvironment;
import org.apache.hadoop.gateway.filter.rewrite.api.UrlRewriter;
import org.apache.hadoop.gateway.filter.rewrite.spi.UrlRewriteContext;
import org.apache.hadoop.gateway.filter.rewrite.spi.UrlRewriteResolver;
import org.apache.hadoop.gateway.util.urltemplate.Params;
import org.apache.hadoop.gateway.util.urltemplate.Parser;
import org.apache.hadoop.gateway.util.urltemplate.Template;
import org.easymock.EasyMock;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

public class UrlRewriteContextImplTest {

  @Test
  public void testResolve() throws Exception {

    UrlRewriteEnvironment environment = EasyMock.createNiceMock( UrlRewriteEnvironment.class );
    EasyMock.expect( environment.resolve( "test-env-param-name" ) ).andReturn( Arrays.asList( "test-env-param-value" ) ).anyTimes();

    UrlRewriteResolver resolver = EasyMock.createNiceMock( UrlRewriteResolver.class );
    EasyMock.expect( resolver.resolve( EasyMock.anyObject(UrlRewriteContext.class), EasyMock.eq( "test-ctx-param-name" ) ) ).andReturn( "test-ctx-param-value" );

    EasyMock.replay( environment, resolver );

    UrlRewriter.Direction direction = UrlRewriter.Direction.OUT;
    Template template = Parser.parse( "scheme://host:port/dir/file" );

    UrlRewriteContextImpl context = new UrlRewriteContextImpl( environment, resolver, direction, template );

    Params params = context.getParameters();
    List<String> values = params.resolve( "test-env-param-name" );
    assertThat( values, notNullValue() );
    assertThat( values.size(), is( 1 ) );
    assertThat( values.get( 0 ), is( "test-env-param-value" ) );

    values = params.resolve( "test-ctx-param-name" );
    assertThat( values, notNullValue() );
    assertThat( values.size(), is( 1 ) );
    assertThat( values.get( 0 ), is( "test-ctx-param-value" ) );
  }

}
