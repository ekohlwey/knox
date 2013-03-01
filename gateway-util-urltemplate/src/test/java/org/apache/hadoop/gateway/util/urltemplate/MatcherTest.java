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
package org.apache.hadoop.gateway.util.urltemplate;


import org.apache.hadoop.test.category.FastTests;
import org.apache.hadoop.test.category.UnitTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.net.URISyntaxException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.core.IsCollectionContaining.hasItem;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

//TODO: Test to make sure that extra unmatched query parameters prevent a match.
@Category( { UnitTests.class, FastTests.class } )
public class MatcherTest {

  private void addTemplate( Matcher<String> matcher, String template ) throws URISyntaxException {
    matcher.add( Parser.parse( template ), template );
  }

  private void assertValidMatch( Matcher<String> matcher, String uri, String template ) throws URISyntaxException {
    if( template == null ) {
      assertThat( matcher.match( Parser.parse( uri ) ), nullValue() );
    } else {
      Template uriTemplate = Parser.parse( uri );
      Matcher<String>.Match match = matcher.match( uriTemplate );
      assertThat( "Expected to find a match.", match, notNullValue() );
      assertThat( match.getValue(), equalTo( template ) );
    }
  }

  @Test
  public void testTopLevelPathGlobMatch() throws Exception {
    Matcher<String> matcher;
    Template patternTemplate, inputTemplate;
    Matcher<String>.Match match;

    patternTemplate = Parser.parse( "{*}://{host}:{*}/{**=**}?{**}" );
    inputTemplate = Parser.parse( "test-scheme://test-input-host:42/test-path/test-file?test-name=test-value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "test-math" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because the path ** should include both test-path and test-file", match, notNullValue() );

    patternTemplate = Parser.parse( "{*}://{host}:{*}/{**}?{**}" );
    inputTemplate = Parser.parse( "test-scheme://test-input-host:42/test-path/test-file?test-name=test-value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "test-math" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because the path ** should include both test-path and test-file", match, notNullValue() );
  }

  @Test
  public void testQueryHandling() throws Exception {
    Matcher<String> matcher;
    Template patternTemplate, inputTemplate;
    Matcher<String>.Match match;

    patternTemplate = Parser.parse( "/path?{query}" );
    inputTemplate = Parser.parse( "/path" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should not match because input does not contain the required query.", match, nullValue() );

    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/path?{query}" ), "T1" );
    matcher.add( Parser.parse( "/path" ), "T2" );
    inputTemplate = Parser.parse( "/path" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because there is an entry in the matcher without a query.", match, notNullValue() );
    assertThat( match.getValue(), equalTo( "T2") );

    patternTemplate = Parser.parse( "/path?{query}" );
    inputTemplate = Parser.parse( "/path?query=value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because input does contain the required query.", match, notNullValue() );
    assertThat( match.getParams().resolve( "query" ), hasItem( "value" ) );
    assertThat( match.getParams().resolve( "query" ).size(), equalTo( 1 ) );

    patternTemplate = Parser.parse( "/path?{*}" );
    inputTemplate = Parser.parse( "/path" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should not match because input does not contain the required query.", match, nullValue() );

    patternTemplate = Parser.parse( "/path?*" );
    inputTemplate = Parser.parse( "/path" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should not match because input does not contain the required query.", match, nullValue() );

    patternTemplate = Parser.parse( "/path?*" );
    inputTemplate = Parser.parse( "/path?query=value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat(
        "Should match because the template has an extra query and the input has a query.",
        match, notNullValue() );
    assertThat(
        "Should not have extracts any parameters since pattern template didn't contain {}",
        match.getParams().resolve( "query" ), nullValue() );

    patternTemplate = Parser.parse( "/path?{*}" );
    inputTemplate = Parser.parse( "/path?query=value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because input does contain the required query.", match, notNullValue() );
    assertThat( match.getParams().resolve( "query" ), hasItem( "value" ) );

    patternTemplate = Parser.parse( "/path?{**}" );
    inputTemplate = Parser.parse( "/path" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because the template has an optional query.", match, notNullValue() );

    patternTemplate = Parser.parse( "/path?**" );
    inputTemplate = Parser.parse( "/path" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because the template has an optional extra query.", match, notNullValue() );

    patternTemplate = Parser.parse( "/path?**" );
    inputTemplate = Parser.parse( "/path?query=value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because the template has an optional extra query.", match, notNullValue() );
    assertThat( match.getParams().resolve( "query" ), nullValue() );

    patternTemplate = Parser.parse( "/path?{**}" );
    inputTemplate = Parser.parse( "/path?query=value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because the template has an optional extra query.", match, notNullValue() );
    assertThat( match.getParams().resolve( "query" ), hasItem( "value" ) );
    assertThat( match.getParams().resolve( "query" ).size(), equalTo( 1 ) );

    patternTemplate = Parser.parse( "/path?{query}&{*}" );
    inputTemplate = Parser.parse( "/path?query=value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should not match because input does not contain the required extra query.", match, nullValue() );

    patternTemplate = Parser.parse( "/path?{query}&{*}" );
    inputTemplate = Parser.parse( "/path?query=value&extra=extra-value" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because input does contain the required query.", match, notNullValue() );
    assertThat( match.getParams().resolve( "query" ), hasItem( "value" ) );
    assertThat( match.getParams().resolve( "query" ).size(), equalTo( 1 ) );

    patternTemplate = Parser.parse( "/path?{query=**}" );
    inputTemplate = Parser.parse( "/path?query=value1&query=value2" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because input does contain the required query.", match, notNullValue() );
    assertThat( match.getParams().resolve( "query" ), hasItem( "value1" ) );
    assertThat( match.getParams().resolve( "query" ), hasItem( "value2" ) );
    assertThat( match.getParams().resolve( "query" ).size(), equalTo( 2 ) );

    patternTemplate = Parser.parse( "/path?{query}" );
    inputTemplate = Parser.parse( "/path?query=value1&query=value2" );
    matcher = new Matcher<String>();
    matcher.add( patternTemplate, "T" );
    match = matcher.match( inputTemplate );
    assertThat( "Should match because input does contain the required query.", match, notNullValue() );
    assertThat( match.getParams().resolve( "query" ), hasItem( "value1" ) );
    assertThat( match.getParams().resolve( "query" ), hasItem( "value2" ) );
    assertThat( match.getParams().resolve( "query" ).size(), equalTo( 2 ) );
  }

  @Test
  public void testMatchCompleteUrl() throws Exception {
    Matcher<String> matcher;
    String pattern, input;
    Template patternTemplate, inputTemplate;
    Matcher<String>.Match match;

    matcher = new Matcher<String>();
    pattern = "foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal#nose";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    input = "foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal#nose";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );

    matcher = new Matcher<String>();
    pattern = "foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal#nose";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );

    input = pattern;
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match, notNullValue() );

    input = "not://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal#nose";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match, nullValue() );
  }

  @Test
  public void testMatch() throws Exception {
    Matcher<String> matcher;
    String pattern, input;
    Template patternTemplate, inputTemplate;
    Matcher<String>.Match match;

    matcher = new Matcher<String>();
    pattern = "path";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    assertThat( matcher.get( patternTemplate ), is( pattern ) );
    input = "path";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );


    matcher = new Matcher<String>();
    pattern = "/path";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    input = "/path";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );

    matcher = new Matcher<String>();
    pattern = "path/path";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    input = "path/path";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );

    matcher = new Matcher<String>();
    pattern = "*/path";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    input = "pathA/path";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );

    matcher = new Matcher<String>();
    pattern = "**/path";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    input = "pathA/pathB/path";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );

    matcher = new Matcher<String>();
    pattern = "path-1/{path=**}/path-4";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    input = "path-1/path-2/path-3/path-4";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );
    assertThat( match.getParams().resolve( "path" ).get( 0 ), equalTo( "path-2" ) );
    assertThat( match.getParams().resolve( "path" ).get( 1 ), equalTo( "path-3" ) );

    matcher = new Matcher<String>();
    pattern = "/";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    input = "/";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );

    matcher = new Matcher<String>();
    pattern = "";
    patternTemplate = Parser.parse( pattern );
    matcher.add( patternTemplate, pattern );
    input = "";
    inputTemplate = Parser.parse( input );
    match = matcher.match( inputTemplate );
    assertThat( match.getTemplate(), sameInstance( patternTemplate ) );
    assertThat( match.getValue(), equalTo( pattern ) );
  }

  @Test
  public void testVariousPatterns() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/webhdfs" ), "/webhdfs" );
    matcher.add( Parser.parse( "/webhdfs/dfshealth.jsp" ), "/webhdfs/dfshealth.jsp" );
    matcher.add( Parser.parse( "/webhdfs/*.jsp" ), "/webhdfs/*.jsp" );
    matcher.add( Parser.parse( "/webhdfs/other.jsp" ), "/webhdfs/other.jsp" );
    matcher.add( Parser.parse( "/webhdfs/*" ), "/webhdfs/*" );
    matcher.add( Parser.parse( "/webhdfs/**" ), "/webhdfs/**" );
    matcher.add( Parser.parse( "/webhdfs/v1/**" ), "/webhdfs/v1/**" );
    matcher.add( Parser.parse( "/webhdfs/**/middle/*.xml" ), "/webhdfs/**/middle/*.xml" );

    assertValidMatch( matcher, "/webhdfs", "/webhdfs" );
    assertValidMatch( matcher, "/webhdfs/dfshealth.jsp", "/webhdfs/dfshealth.jsp" );
    assertValidMatch( matcher, "/webhdfs/v1", "/webhdfs/*" ); // The star should be picked in preference to the glob.
    assertValidMatch( matcher, "/webhdfs/some.jsp", "/webhdfs/*.jsp" );
    assertValidMatch( matcher, "/webhdfs/other.jsp", "/webhdfs/other.jsp" );
    assertValidMatch( matcher, "/webhdfs/path/some.jsp", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/path/middle/some.jsp", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/path/middle/some.xml", "/webhdfs/**/middle/*.xml" );
    assertValidMatch( matcher, "/webhdfs/path/to/file", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/v1/path/to/file", "/webhdfs/v1/**" );
  }

  @Test
  public void testStar() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/webhdfs/*" ), "/webhdfs/*" );
    assertValidMatch( matcher, "/webhdfs/*", "/webhdfs/*" );
    assertValidMatch( matcher, "/webhdfs/file", "/webhdfs/*" );
    assertValidMatch( matcher, "/webhdfs/path/", "/webhdfs/*" );
    assertValidMatch( matcher, "/webhdfs/path/file", null );
    assertValidMatch( matcher, "/webhdfs/path/path/", null );
  }

  @Test
  public void testGlob() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/webhdfs/**" ), "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/file", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/path/", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/path/file", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/path/path/", "/webhdfs/**" );
  }

  @Test
  public void testMatrixParam() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/webhdfs/**" ), "/webhdfs/**" );
    matcher.add( Parser.parse( "/webhdfs/browseDirectory.jsp;dn=*" ), "/webhdfs/browseDirectory.jsp;dn=*" );
    assertValidMatch( matcher, "/webhdfs/browseDirectory.jsp;dn=X", "/webhdfs/browseDirectory.jsp;dn=*" );
  }

  @Test
  public void testTwoGlobsAtDifferentDepths() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/webhdfs/**" ), "/webhdfs/**" );
    matcher.add( Parser.parse( "/webhdfs/v1/**" ), "/webhdfs/v1/**" );
    assertValidMatch( matcher, "/webhdfs/file", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/v1/file", "/webhdfs/v1/**" );

    // Reverse the put order.
    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/webhdfs/v1/**" ), "/webhdfs/v1/**" );
    matcher.add( Parser.parse( "/webhdfs/**" ), "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/file", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/v1/file", "/webhdfs/v1/**" );
  }

  @Test
  public void testGlobsVsStarsAtSameDepth() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/webhdfs/*" ), "/webhdfs/*" );
    matcher.add( Parser.parse( "/webhdfs/**" ), "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/file", "/webhdfs/*" ); // The star should be picked in preference to the glob.
    assertValidMatch( matcher, "/webhdfs/path/file", "/webhdfs/**" );

    // Reverse the put order.
    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/webhdfs/**" ), "/webhdfs/**" );
    matcher.add( Parser.parse( "/webhdfs/*" ), "/webhdfs/*" );
    assertValidMatch( matcher, "/webhdfs/path/file", "/webhdfs/**" );
    assertValidMatch( matcher, "/webhdfs/file", "/webhdfs/*" );
  }

  @Test
  public void testMatchingPatternsWithinPathSegments() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/path/{file}" ), "default" );
    assertValidMatch( matcher, "/path/file-name", "default" );

    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/path/{file=*}" ), "*" );
    assertValidMatch( matcher, "/path/some-name", "*" );

    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/path/{more=**}" ), "**" );
    assertValidMatch( matcher, "/path/some-path/some-name", "**" );

    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "/path/{regex=prefix*suffix}" ), "regex" );
    assertValidMatch( matcher, "/path/prefix-middle-suffix", "regex" );
    assertValidMatch( matcher, "/path/not-prefix-middle-suffix", null );
  }

  @Test
  public void testMatchingPatternsWithinQuerySegments() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    matcher.add( Parser.parse( "?query={queryParam}" ), "default" );
    assertValidMatch( matcher, "?query=value", "default" );

    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "?query={queryParam=*}" ), "*" );
    assertValidMatch( matcher, "?query=some-value", "*" );

    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "?query={queryParam=**}" ), "**" );
    assertValidMatch( matcher, "?query=some-value", "**" );

    matcher = new Matcher<String>();
    matcher.add( Parser.parse( "?query={queryParam=prefix*suffix}" ), "regex" );
    assertValidMatch( matcher, "?query=prefix-middle-suffix", "regex" );
    assertValidMatch( matcher, "?query=not-prefix-middle-suffix", null );
  }

  @Test
  public void testMatchingForTemplatesThatVaryOnlyByQueryParams() throws URISyntaxException {
    Matcher<String> matcher = new Matcher<String>();
    addTemplate( matcher, "?one={queryParam}" );
    addTemplate( matcher, "?two={queryParam}" );

    assertValidMatch( matcher, "?one=value", "?one={queryParam}" );
    assertValidMatch( matcher, "?two=value", "?two={queryParam}" );
    assertValidMatch( matcher, "?three=value", null );
    assertValidMatch( matcher, "?", null );
  }

  @Test
  public void testFullUrlExtraction() throws URISyntaxException {
    Template template;
    Template input;
    Matcher<?> matcher;
    Matcher<?>.Match match;
    Params params;

    template = Parser.parse( "{scheme}://{username}:{password}@{host}:{port}/{root}/{path}/{file}?queryA={paramA}&queryB={paramB}#{fragment}" );
    input = Parser.parse( "http://horton:hadoop@hortonworks.com:80/top/middle/end?queryA=valueA&queryB=valueB#section" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();

    assertThat( params.getNames(), hasItem( "scheme" ) );
    assertThat( params.resolve( "scheme" ), hasItem( "http" ) );
    assertThat( params.getNames(), hasItem( "username" ) );
    assertThat( params.resolve( "username" ), hasItem( "horton" ) );
    assertThat( params.getNames(), hasItem( "password" ) );
    assertThat( params.resolve( "password" ), hasItem( "hadoop" ) );
    assertThat( params.getNames(), hasItem( "host" ) );
    assertThat( params.resolve( "host" ), hasItem( "hortonworks.com" ) );
    assertThat( params.getNames(), hasItem( "port" ) );
    assertThat( params.resolve( "port" ), hasItem( "80" ) );
    assertThat( params.getNames(), hasItem( "root" ) );
    assertThat( params.resolve( "root" ), hasItem( "top" ) );
    assertThat( params.getNames(), hasItem( "path" ) );
    assertThat( params.resolve( "path" ), hasItem( "middle" ) );
    assertThat( params.getNames(), hasItem( "file" ) );
    assertThat( params.resolve( "file" ), hasItem( "end" ) );
    assertThat( params.getNames(), hasItem( "paramA" ) );
    assertThat( params.resolve( "paramA" ), hasItem( "valueA" ) );
    assertThat( params.getNames(), hasItem( "paramB" ) );
    assertThat( params.resolve( "paramB" ), hasItem( "valueB" ) );
    assertThat( params.getNames(), hasItem( "fragment" ) );
    assertThat( params.resolve( "fragment" ), hasItem( "section" ) );
    assertThat( params.getNames().size(), equalTo( 11 ) );
  }

  @Test
  public void testMultipleDoubleStarPathMatching() throws URISyntaxException {
    Template template;
    Template input;
    Matcher<?> matcher;
    Matcher<String> stringMatcher;
    Matcher<?>.Match match;

//    template = Parser.parse( "*://*:*/**/namenode/api/v1/**?**" );
//    input = Parser.parse( "http://localhost:53221/gateway/cluster/namenode/api/v1/tmp/GatewayWebHdfsFuncTest/testBasicHdfsUseCase/dir?user.name=hdfs&op=MKDIRS" );
//    matcher = new Matcher<String>( template, "test-value" );
//    match = matcher.match( input );
//    assertThat( (String)match.getValue(), is( "test-value" ) );
//
//    template = Parser.parse( "*://*:*/**/namenode/api/v1/{path=**}?{**=*}" );
//    input = Parser.parse( "http://localhost:53221/gateway/cluster/namenode/api/v1/tmp/GatewayWebHdfsFuncTest/testBasicHdfsUseCase/dir?user.name=hdfs&op=MKDIRS" );
//    matcher = new Matcher<String>( template, "test-value-2" );
//    match = matcher.match( input );
//    assertThat( (String)match.getValue(), is( "test-value-2" ) );
//
//    stringMatcher = new Matcher<String>();
//    template = Parser.parse( "*://*:*/**/datanode/api/v1/{path=**}?host={host=*}&port={port=*}&{**=*}" );
//    stringMatcher.add( template, "test-value-C" );
//    template = Parser.parse( "*://*:*/**/namenode/api/v1/{path=**}?{**=*}" );
//    stringMatcher.add( template, "test-value-B" );
//    input = Parser.parse( "http://localhost:53221/gateway/cluster/namenode/api/v1/tmp/GatewayWebHdfsFuncTest/testBasicHdfsUseCase/dir?user.name=hdfs&op=MKDIRS" );
//    match = stringMatcher.match( input );
//    assertThat( match.getValue(), notNullValue() );
//    assertThat( (String)match.getValue(), is( "test-value-B" ) );

    // This is just a reverse of the above.  The order caused a bug.
    stringMatcher = new Matcher<String>();
    template = Parser.parse( "*://*:*/**/namenode/api/v1/{path=**}?{**=*}" );
    stringMatcher.add( template, "test-value-B" );
    template = Parser.parse( "*://*:*/**/datanode/api/v1/{path=**}?host={host=*}&port={port=*}&{**=*}" );
    stringMatcher.add( template, "test-value-C" );
    input = Parser.parse( "http://localhost:53221/gateway/cluster/namenode/api/v1/tmp/GatewayWebHdfsFuncTest/testBasicHdfsUseCase/dir?user.name=hdfs&op=MKDIRS" );
    match = stringMatcher.match( input );
    assertThat( match.getValue(), notNullValue() );
    assertThat( (String)match.getValue(), is( "test-value-B" ) );

  }

  @Test
  public void testPathExtraction() throws Exception {
    Template template;
    Template input;
    Matcher<?> matcher;
    Matcher<?>.Match match;
    Params params;

    template = Parser.parse( "{path-queryParam}" );
    input = Parser.parse( "path-value" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();
    assertThat( params, notNullValue() );
    assertThat( params.getNames().size(), equalTo( 1 ) );
    assertThat( params.getNames(), hasItem( "path-queryParam" ) );
    assertThat( params.resolve( "path-queryParam" ).size(), equalTo( 1 ) );
    assertThat( params.resolve( "path-queryParam" ), hasItem( "path-value" ) );

    template = Parser.parse( "/some-path/{path-queryParam}" );
    input = Parser.parse( "/some-path/path-value" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();
    assertThat( params, notNullValue() );
    assertThat( params.getNames().size(), equalTo( 1 ) );
    assertThat( params.getNames(), hasItem( "path-queryParam" ) );
    assertThat( params.resolve( "path-queryParam" ).size(), equalTo( 1 ) );
    assertThat( params.resolve( "path-queryParam" ), hasItem( "path-value" ) );

    template = Parser.parse( "/some-path/{path-queryParam}/some-other-path" );
    input = Parser.parse( "/some-path/path-value/some-other-path" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();
    assertThat( params, notNullValue() );
    assertThat( params.getNames().size(), equalTo( 1 ) );
    assertThat( params.getNames(), hasItem( "path-queryParam" ) );
    assertThat( params.resolve( "path-queryParam" ).size(), equalTo( 1 ) );
    assertThat( params.resolve( "path-queryParam" ), hasItem( "path-value" ) );

    template = Parser.parse( "{path=**}" );
    input = Parser.parse( "A/B" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();
    assertThat( params, notNullValue() );
    assertThat( params.getNames().size(), equalTo( 1 ) );
    assertThat( params.getNames(), hasItem( "path" ) );
    assertThat( params.resolve( "path" ).size(), equalTo( 2 ) );
    assertThat( params.resolve( "path" ), hasItem( "A" ) );
    assertThat( params.resolve( "path" ), hasItem( "B" ) );

    template = Parser.parse( "/top/{mid=**}/end" );
    input = Parser.parse( "/top/A/B/end" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();
    assertThat( params, notNullValue() );
    assertThat( params.getNames().size(), equalTo( 1 ) );
    assertThat( params.getNames(), hasItem( "mid" ) );
    assertThat( params.resolve( "mid" ).size(), equalTo( 2 ) );
    assertThat( params.resolve( "mid" ), hasItem( "A" ) );
    assertThat( params.resolve( "mid" ), hasItem( "B" ) );
  }

  @Test
  public void testQueryExtraction() throws Exception {
    Template template;
    Template input;
    Matcher<?> matcher;
    Matcher<?>.Match match;
    Params params;

    template = Parser.parse( "?query-queryParam={queryParam-name}" );
    input = Parser.parse( "?query-queryParam=queryParam-value" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();
    assertThat( params, notNullValue() );
    assertThat( params.getNames().size(), equalTo( 1 ) );
    assertThat( params.getNames(), hasItem( "queryParam-name" ) );
    assertThat( params.resolve( "queryParam-name" ).size(), equalTo( 1 ) );
    assertThat( params.resolve( "queryParam-name" ), hasItem( "queryParam-value" ) );

    template = Parser.parse( "?query-queryParam={queryParam-name}" );
    input = Parser.parse( "?query-queryParam=queryParam-value" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();
    assertThat( params, notNullValue() );
    assertThat( params.getNames().size(), equalTo( 1 ) );
    assertThat( params.getNames(), hasItem( "queryParam-name" ) );
    assertThat( params.resolve( "queryParam-name" ).size(), equalTo( 1 ) );
    assertThat( params.resolve( "queryParam-name" ), hasItem( "queryParam-value" ) );
  }

  @Test
  public void testEdgeCaseExtraction() throws Exception {
    Template template;
    Template input;
    Matcher<?> matcher;
    Matcher<?>.Match match;
    Params params;

    template = Parser.parse( "" );
    input = Parser.parse( "" );
    matcher = new Matcher<Void>( template, null );
    match = matcher.match( input );
    params = match.getParams();
    assertThat( params, notNullValue() );
    assertThat( params.getNames().size(), equalTo( 0 ) );
  }

}
