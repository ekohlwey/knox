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
package org.apache.hadoop.gateway.filter.rewrite.api;

import org.apache.hadoop.test.mock.MockInteraction;
import org.apache.hadoop.test.mock.MockServlet;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.testing.HttpTester;
import org.eclipse.jetty.testing.ServletTester;
import org.eclipse.jetty.util.ArrayQueue;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import javax.servlet.DispatcherType;
import java.net.URL;
import java.util.EnumSet;

import static org.junit.Assert.fail;

public class UrlRewriteServletContextListenerTest {

  private ServletTester server;
  private HttpTester request;
  private HttpTester response;
  private ArrayQueue<MockInteraction> interactions;
  private MockInteraction interaction;

  private static URL getTestResource( String name ) {
    name = UrlRewriteServletFilterTest.class.getName().replaceAll( "\\.", "/" ) + "/" + name;
    URL url = ClassLoader.getSystemResource( name );
    return url;
  }

  @Before
  public void setUp() throws Exception {
    String descriptorUrl = getTestResource( "rewrite.xml" ).toExternalForm();

    server = new ServletTester();
    server.setContextPath( "/" );
    server.getContext().addEventListener( new UrlRewriteServletContextListener() );
    server.getContext().setInitParameter(
        UrlRewriteServletContextListener.DESCRIPTOR_LOCATION_INIT_PARAM_NAME, descriptorUrl );

    FilterHolder filter = server.addFilter( UrlRewriteServletFilter.class, "/*", EnumSet.of( DispatcherType.REQUEST ) );
    filter.setFilter( new UrlRewriteServletFilter() );

    interactions = new ArrayQueue<MockInteraction>();

    ServletHolder servlet = server.addServlet( MockServlet.class, "/" );
    servlet.setServlet( new MockServlet( "mock-servlet", interactions ) );
    servlet.setInitParameter(
        UrlRewriteServletContextListener.DESCRIPTOR_LOCATION_INIT_PARAM_NAME,
        getTestResource( "rewrite.xml" ).toExternalForm() );

    server.start();

    interaction = new MockInteraction();
    request = new HttpTester();
    response = new HttpTester();
  }

  @After
  public void tearDown() throws Exception {
    server.stop();
  }

  @Test
  @Ignore("TODO")
  public void testProvider() throws Exception {
    fail( "TODO" );
  }

}
