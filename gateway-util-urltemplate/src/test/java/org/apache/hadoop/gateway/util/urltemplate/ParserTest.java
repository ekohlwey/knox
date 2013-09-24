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
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.net.URISyntaxException;
import java.util.Iterator;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

@Category( { UnitTests.class, FastTests.class } )
public class ParserTest {

  private void assertBasics(
      Template template,
      boolean isAbsolute,
      boolean isDirectory,
      boolean hasQuery,
      int pathSegmentsSize,
      int querySegmentsSize ) {
    assertThat( "Incorrect isAbsolute value.", template.isAbsolute(), is( isAbsolute ) );
    assertThat( "Incorrect isDirectory value.", template.isDirectory(), is( isDirectory ) );
    assertThat( "Incorrect hasQuery value.", template.hasQuery(), is( hasQuery ) );
    assertThat( "Incorrect path size.", template.getPath().size(), is( pathSegmentsSize ) );
    assertThat( "Incorrect query size.", template.getQuery().size(), is( querySegmentsSize ) );
  }

  public void assertPath(
      Template template,
      int index,
      String paramName,
      String valuePattern ) {
    Path segment = template.getPath().get( index );
    assertThat( "Incorrect template queryParam name.", segment.getParamName(), is( paramName ) );
    assertThat( "Incorrect template value pattern.", segment.getFirstValue().getPattern(), is( valuePattern ) );
  }

  public void assertPath(
      Template template,
      int index,
      String paramName,
      String valuePattern,
      int type,
      int minRequired,
      int maxAllowed ) {
    Path segment = template.getPath().get( index );
    assertThat( "Param name wrong.", segment.getParamName(), is( paramName ) );
    assertThat( "Value pattern wrong.", segment.getFirstValue().getPattern(), is( valuePattern ) );
    assertThat( "Segment type wrong.", segment.getFirstValue().getType(), is( type ) );
//    assertThat( "Segment min required wrong.", segment.getMinRequired(), is( minRequired ) );
//    assertThat( "Segment max allowed wrong.", segment.getMaxAllowed(), is( maxAllowed ) );
  }

  public void assertQuery(
      Template template,
      String queryName,
      String paramName,
      String valuePattern ) {
    Query segment = template.getQuery().get( queryName );
    assertThat( "Query name wrong.", segment.getQueryName(), is( queryName ));
    assertThat( "Param name wrong.", segment.getParamName(), is( paramName ));
    assertThat( "value pattern wrong.", segment.getFirstValue().getPattern(), is( valuePattern ));
  }

  public void assertQuery(
      Template template,
      String queryName,
      String paramName,
      String valuePattern,
      int type,
      int minRequired,
      int maxAllowed ) {
    Query segment = template.getQuery().get( queryName );
    assertThat( "Query name wrong.", segment.getQueryName(), is( queryName ));
    assertThat( "Param name wrong.", segment.getParamName(), is( paramName ));
    assertThat( "value pattern wrong.", segment.getFirstValue().getPattern(), is( valuePattern ));
    assertThat( "Segment type wrong.", segment.getFirstValue().getType(), is( type ) );
//    assertThat( "Segment min required wrong.", segment.getMinRequired(), is( minRequired ) );
//    assertThat( "Segment max allowed wrong.", segment.getMaxAllowed(), is( maxAllowed ) );
  }

  @Test
  public void testCompleteUrl() throws URISyntaxException {
    String text;
    Template template;
    Parser parser = new Parser();

    text = "foo://username:password@example.com:8042/over/there/index.dtb?type=animal&name=narwhal#nose";
    template = parser.parseTemplate( text );
    assertBasics( template, true, false, true, 3, 2 );
  }

  @Ignore( "TODO" )
  @Test
  public void testInvalidPatterns() {
    //TODO: ? in wrong spot.
    //TODO: & in wrong spots.
  }

  @Ignore( "TODO" )
  @Test
  public void testRegexPatterns() {
  }

  @Test
  public void testTemplates() throws URISyntaxException {
    String text;
    Template template;

    text = "{path}";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertPath( template, 0, "path", "**" );

    text = "{pathA}/{pathB}";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 2, 0 );
    assertPath( template, 0, "pathA", "**" );
    assertPath( template, 1, "pathB", "**" );

    text = "?paramA={valueA}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    assertQuery( template, "paramA", "valueA", "**" );

    text = "?paramA={valueA}&paramB={valueB}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 2 );
    assertQuery( template, "paramA", "valueA", "**" );
    assertQuery( template, "paramB", "valueB", "**" );

    text = "?paramA={valueA}?paramB={valueB}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 2 );
    assertQuery( template, "paramA", "valueA", "**" );
    assertQuery( template, "paramB", "valueB", "**" );

    text = "{pathA}?paramA={valueA}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 1, 1 );
    assertPath( template, 0, "pathA", "**" );
    assertQuery( template, "paramA", "valueA", "**" );
  }

  @Test
  public void testStaticPatterns() throws Exception {
    Parser parser = new Parser();
    String text;
    Template template;

    text = "";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, false, 0, 0 );

    text = "/";
    template = parser.parseTemplate( text );
    assertBasics( template, true, true, false, 0, 0 );

    text = "?";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, true, 0, 0 );

    text = "#";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getFragment(), nullValue() );

    text = "path";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertPath( template, 0, "", "path" );

    text = "/path";
    template = parser.parseTemplate( text );
    assertBasics( template, true, false, false, 1, 0 );
    assertPath( template, 0, "", "path" );

//    text = "//path";
//    template = parser.parseTemplate( text );
//    assertBasics( template, true, false, false, 1, 0 );
//    assertPath( template, 0, "", "path" );

    text = "path/";
    template = parser.parseTemplate( text );
    assertBasics( template, false, true, false, 1, 0 );
    assertPath( template, 0, "", "path" );

    text = "path//";
    template = parser.parseTemplate( text );
    assertBasics( template, false, true, false, 1, 0 );
    assertPath( template, 0, "", "path" );

    text = "/path/";
    template = parser.parseTemplate( text );
    assertBasics( template, true, true, false, 1, 0 );
    assertPath( template, 0, "", "path" );

//    text = "//path//";
//    template = parser.parseTemplate( text );
//    assertBasics( template, true, true, false, 1, 0 );
//    assertPath( template, 0, "", "path" );

    text = "pathA/pathB";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, false, 2, 0 );
    assertPath( template, 0, "", "pathA" );
    assertPath( template, 1, "", "pathB" );

    text = "pathA//pathB";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, false, 2, 0 );
    assertPath( template, 0, "", "pathA" );
    assertPath( template, 1, "", "pathB" );

    text = "/pathA/pathB";
    template = parser.parseTemplate( text );
    assertBasics( template, true, false, false, 2, 0 );
    assertPath( template, 0, "", "pathA" );
    assertPath( template, 1, "", "pathB" );

    text = "/pathA//pathB";
    template = parser.parseTemplate( text );
    assertBasics( template, true, false, false, 2, 0 );
    assertPath( template, 0, "", "pathA" );
    assertPath( template, 1, "", "pathB" );

    text = "pathA/pathB/";
    template = parser.parseTemplate( text );
    assertBasics( template, false, true, false, 2, 0 );
    assertPath( template, 0, "", "pathA" );
    assertPath( template, 1, "", "pathB" );

    text = "pathA//pathB/";
    template = parser.parseTemplate( text );
    assertBasics( template, false, true, false, 2, 0 );
    assertPath( template, 0, "", "pathA" );
    assertPath( template, 1, "", "pathB" );

    text = "/pathA/pathB/";
    template = parser.parseTemplate( text );
    assertBasics( template, true, true, false, 2, 0 );
    assertPath( template, 0, "", "pathA" );
    assertPath( template, 1, "", "pathB" );

    text = "/pathA//pathB/";
    template = parser.parseTemplate( text );
    assertBasics( template, true, true, false, 2, 0 );
    assertPath( template, 0, "", "pathA" );
    assertPath( template, 1, "", "pathB" );

    text = "/?";
    template = parser.parseTemplate( text );
    assertBasics( template, true, true, true, 0, 0 );

//    text = "//??";
//    template = parser.parseTemplate( text );
//    assertBasics( template, true, true, true, 0, 0 );

    text = "?name=value";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, true, 0, 1 );
    assertQuery( template, "name", "", "value" );

    text = "?name1=value1&name2=value2";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, true, 0, 2 );
    assertQuery( template, "name1", "", "value1" );
    assertQuery( template, "name2", "", "value2" );

    text = "?name1=value1&&name2=value2";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, true, 0, 2 );
    assertQuery( template, "name1", "", "value1" );
    assertQuery( template, "name2", "", "value2" );

    text = "/?name=value";
    template = parser.parseTemplate( text );
    assertBasics( template, true, true, true, 0, 1 );
    assertQuery( template, "name", "", "value" );

    text = "/?name1=value1&name2=value2";
    template = parser.parseTemplate( text );
    assertBasics( template, true, true, true, 0, 2 );
    assertQuery( template, "name1", "", "value1" );
    assertQuery( template, "name2", "", "value2" );
  }

  @Test
  public void testParameterizedPathTemplatesWithWildcardAndRegex() throws URISyntaxException {
    String text;
    Template template;

    text = "{path}";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertPath( template, 0, "path", "**", Segment.GLOB, 1, 1 );

    text = "{path=static}";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertPath( template, 0, "path", "static", Segment.STATIC, 1, 1 );

    text = "{path=*}";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertPath( template, 0, "path", "*", Segment.STAR, 1, 1 );

    text = "{path=**}";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertPath( template, 0, "path", "**", Segment.GLOB, 0, Integer.MAX_VALUE );

    text = "{path=wild*card}";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertPath( template, 0, "path", "wild*card", Segment.REGEX, 1, 1 );
  }

  @Test
  public void testParameterizedQueryTemplatesWithWildcardAndRegex() throws URISyntaxException {
    String text;
    Template template;

    text = "?query={queryParam}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    assertQuery( template, "query", "queryParam", "**", Segment.GLOB, 1, 1 );

    text = "?query={queryParam=static}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    assertQuery( template, "query", "queryParam", "static", Segment.STATIC, 1, 1 );

    text = "?query={queryParam=*}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    assertQuery( template, "query", "queryParam", "*", Segment.STAR, 1, 1 );

    text = "?query={queryParam=**}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    assertQuery( template, "query", "queryParam", "**", Segment.GLOB, 0, Integer.MAX_VALUE );

    text = "?query={queryParam=wild*card}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    assertQuery( template, "query", "queryParam", "wild*card", Segment.REGEX, 1, 1 );
  }

  @Test
  public void testGlobPattern() throws URISyntaxException {
    String text;
    Template template;

    text = "**";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );

    text = "/**";
    template = Parser.parse( text );
    assertBasics( template, true, false, false, 1, 0 );

    text = "**/";
    template = Parser.parse( text );
    assertBasics( template, false, true, false, 1, 0 );

    text = "/**/";
    template = Parser.parse( text );
    assertBasics( template, true, true, false, 1, 0 );

    text = "/**/path";
    template = Parser.parse( text );
    assertBasics( template, true, false, false, 2, 0 );
  }

  @Ignore( "TODO" )
  @Test
  public void testPatternsWithSchemeAndAuthority() throws URISyntaxException {
    String text;
    Template template;

    text = "http:";
    template = Parser.parse( text );

    text = "http:/path";
    template = Parser.parse( text );

    text = "http://host";
    template = Parser.parse( text );

    text = "http://host/";
    template = Parser.parse( text );

    text = "http://host:80";
    template = Parser.parse( text );

    text = "http://host:80/";
    template = Parser.parse( text );


    text = "{scheme}:";
    template = Parser.parse( text );

    text = "{scheme}:/{path}";
    template = Parser.parse( text );

    text = "{scheme}://{host}";
    template = Parser.parse( text );

    text = "{scheme}://{host}/";
    template = Parser.parse( text );

    text = "{scheme}://{host}:{port}";
    template = Parser.parse( text );

    text = "{scheme}://{host}:{port}/";
    template = Parser.parse( text );


    text = "{scheme=http}:/{path=index.html}";
    template = Parser.parse( text );

    text = "{scheme=http}://{host=*.com}";
    template = Parser.parse( text );

    text = "{scheme=https}://{host=*.edu}/";
    template = Parser.parse( text );

    text = "{scheme=rmi}://{host=*}:{port=80}";
    template = Parser.parse( text );

    text = "{scheme=ftp}://{host=localhost*}:{port=*80}/";
    template = Parser.parse( text );
  }

  @Test
  public void testAuthority() throws URISyntaxException {
    String text;
    Template template;
    String image;

    text = "//";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );

    text = "//:@:";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );

    text = "//host";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "host" ) );
    assertThat( template.getPort(), nullValue() );

    text = "//@host";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "host" ) );
    assertThat( template.getPort(), nullValue() );

    text = "//@:80";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort().getFirstValue().getPattern(), is( "80" ) );

    text = "//username@";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername().getFirstValue().getPattern(), is( "username" ) );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );

    text = "//:password@";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword().getFirstValue().getPattern(), is( "password" ) );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );

    text = "//{host}:{port}";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost().getParamName(), is( "host" ) );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPort().getParamName(), is( "port" ) );
    assertThat( template.getPort().getFirstValue().getPattern(), is( "*" ) );
    image = template.toString();
    assertThat( image, is( "//{host=*}:{port=*}" ) );

    text = "{host}:{port}";
    template = Parser.parse( text );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost().getParamName(), is( "host" ) );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPort().getParamName(), is( "port" ) );
    assertThat( template.getPort().getFirstValue().getPattern(), is( "*" ) );
    image = template.toString();
    assertThat( image, is( "{host=*}:{port=*}" ) );
  }

  @Test
  public void testQuery() throws URISyntaxException {
    String text;
    Template template;
    Query query;
    Iterator<Segment.Value> values;
    Segment.Value value;

    text = "?queryName";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    query = template.getQuery().get( "queryName" );
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "queryName" ) );
    assertThat( query.getParamName(), is( "" ) );
    assertThat( query.getFirstValue().getPattern(), nullValue() ); //is( "*" ) );

    text = "?query=value1&query=value2";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    query = template.getQuery().get( "query" );
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "query" ) );
    assertThat( query.getParamName(), is( "" ) );
    values = query.getValues().iterator();
    value = values.next();
    assertThat( value.getPattern(), is( "value1" ) );
    value = values.next();
    assertThat( value.getPattern(), is( "value2" ) );
    assertThat( values.hasNext(), is( false ) );
  }

  @Test
  public void testFragment() throws URISyntaxException {
    String text;
    Template template;

    text = "#fragment";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getFragment().getFirstValue().getPattern(), is( "fragment" ) );
  }

  @Test
  public void testEdgeCases() throws URISyntaxException {
    Parser parser = new Parser();
    String text;
    Template template;

    text = "//";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );

    text = "??";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );

    text = "##";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getFragment().getFirstValue().getPattern(), is( "#" ) );

    text = "??name=value";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    assertQuery( template, "name", "", "value" );

    text = "//?";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );

    text = "//#";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );

    text = ":";
    template = parser.parseTemplate( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertThat( template.hasScheme(), is( false ) );
    assertThat( template.getScheme(), nullValue() );
    assertThat( template.hasAuthority(), is( false ) );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );
    assertThat( template.getPath().get( 0 ).getFirstValue().getPattern(), is( ":" ) );
    assertThat( template.toString(), is( ":" ) );

    text = ":?";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 1, 0 );
    assertThat( template.hasScheme(), is( false ) );
    assertThat( template.getScheme(), nullValue() );
    assertThat( template.getPath().get( 0 ).getFirstValue().getPattern(), is( ":" ) );
    assertThat( template.hasQuery(), is( true ) );

    text = ":#";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertThat( template.hasScheme(), is( false ) );
    assertThat( template.getScheme(), nullValue() );
    assertThat( template.getPath().get( 0 ).getFirstValue().getPattern(), is( ":" ) );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getFragment(), nullValue() );

    text = "http:?";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    assertThat( template.hasScheme(), is( true ) );
    assertThat( template.getScheme().getFirstValue().getPattern(), is( "http" ) );
    assertThat( template.hasQuery(), is( true ) );

    text = "http:#";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasScheme(), is( true ) );
    assertThat( template.getScheme().getFirstValue().getPattern(), is( "http" ) );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getFragment(), nullValue() );

    text = "scheme:path?";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 1, 0 );

    text = "scheme:path#";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 1, 0 );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getFragment(), nullValue() );

    text = "//host/";
    template = Parser.parse( text );
    assertBasics( template, true, true, false, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "host" ) );

    text = "//host?";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "host" ) );

    text = "//host#";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getFragment(), nullValue() );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "host" ) );

    text = "///";
    template = Parser.parse( text );
    assertBasics( template, true, true, false, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );

    text = "//:";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );

    text = "//?";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );

    text = "//#";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getFragment(), nullValue() );

    text = "//:/";
    template = Parser.parse( text );
    assertBasics( template, true, true, false, 0, 0 );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getHost(), nullValue() );

    text = "//:?";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    assertThat( template.getHost(), nullValue() );

    text = "//:#";
    template = Parser.parse( text );
    assertBasics( template, false, false, false, 0, 0 );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getHost(), nullValue() );

    text = "///#";
    template = Parser.parse( text );
    assertBasics( template, true, true, false, 0, 0 );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getFragment(), nullValue() );

    text = "///path#";
    template = Parser.parse( text );
    assertBasics( template, true, false, false, 1, 0 );
    assertThat( template.hasFragment(), is( true ) );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getFragment(), nullValue() );

    text = "///?";
    template = Parser.parse( text );
    assertBasics( template, true, true, true, 0, 0 );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getFragment(), nullValue() );

    text = "///path?";
    template = Parser.parse( text );
    assertBasics( template, true, false, true, 1, 0 );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getFragment(), nullValue() );
  }

  @Test
  public void testQueryRemainder() throws URISyntaxException {
    String text;
    Template template;
    Query query;

    text = "?*";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    query = template.getExtra();
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "*" ) );
    assertThat( query.getParamName(), is( "" ) );
    assertThat( query.getFirstValue().getPattern(), nullValue() ); //is( "*" ) );

    text = "?**";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    query = template.getExtra();
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "**" ) );
    assertThat( query.getParamName(), is( "" ) );
    assertThat( query.getFirstValue().getPattern(), nullValue() ); //is( "*" ) );

    text = "?{*}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    query = template.getExtra();
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "*" ) );
    assertThat( query.getParamName(), is( "*" ) );
    assertThat( query.getFirstValue().getPattern(), is( "**" ) );

    text = "?{**}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    query = template.getExtra();
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "**" ) );
    assertThat( query.getParamName(), is( "**" ) );
    assertThat( query.getFirstValue().getPattern(), is( "**" ) );

    text = "?*={*}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    query = template.getExtra();
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "*" ) );
    assertThat( query.getParamName(), is( "*" ) );
    assertThat( query.getFirstValue().getPattern(), is( "**" ) );

    text = "?**={**}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    query = template.getExtra();
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "**" ) );
    assertThat( query.getParamName(), is( "**" ) );
    assertThat( query.getFirstValue().getPattern(), is( "**" ) );

    text = "?**={**=**}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 0 );
    query = template.getExtra();
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "**" ) );
    assertThat( query.getParamName(), is( "**" ) );
    assertThat( query.getFirstValue().getPattern(), is( "**" ) );
  }

  @Test
  public void testSimplifiedQuerySyntax() throws URISyntaxException {
    String text;
    Template template;
    Query query;

    text = "?{queryParam}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    query = template.getQuery().get( "queryParam" );
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "queryParam" ) );
    assertThat( query.getParamName(), is( "queryParam" ) );
    assertThat( query.getFirstValue().getPattern(), is( "**" ) );

    text = "?{queryParam=value}";
    template = Parser.parse( text );
    assertBasics( template, false, false, true, 0, 1 );
    query = template.getQuery().get( "queryParam" );
    assertThat( query, notNullValue() );
    assertThat( query.getQueryName(), is( "queryParam" ) );
    assertThat( query.getParamName(), is( "queryParam" ) );
    assertThat( query.getFirstValue().getPattern(), is( "value" ) );
  }

  @Test
  public void testAllWildcardUseCases() throws URISyntaxException {
    Template template = Parser.parse( "*://*:*/**?**" );
    assertThat( template, notNullValue() );

    template = Parser.parse( "*://*:*/**/path?{**}" );
    assertThat( template, notNullValue() );

    template = Parser.parse( "*://*:*/**/webhdfs/v1/?{**}" );
    assertThat( template, notNullValue() );

  }

  @Test
  public void testQueryNameWithoutValue() throws URISyntaxException {
    Parser parser = new Parser();
    Template template;
    String string;
    Expander expander = new Expander();

    template = parser.parseTemplate( "*://*:*/**?X" );
    assertThat( template.hasScheme(), is( true ) );
    assertThat( template.getScheme().getParamName(), is( "" ) );
    assertThat( template.getScheme().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getHost().getParamName(), is( "" ) );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPort().getParamName(), is( "" ) );
    assertThat( template.getPort().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPath().size(), is( 1 ) );
    assertThat( template.getPath().get( 0 ).getParamName(), is( "" ) );
    assertThat( template.getPath().get( 0 ).getFirstValue().getPattern(), is( "**" ) );
    assertThat( template.hasAuthority(), is( true ) );

    assertThat( template, notNullValue() );
    assertThat( template.getQuery().get( "X" ), notNullValue() );
    string = expander.expandToString( template, null, null );
    assertThat( string, is( "*://*:*/**?X" ) );

    template = Parser.parse( "*://*:*/**?X=" );
    assertThat( template, notNullValue() );
    assertThat( template.getQuery().get( "X" ), notNullValue() );
    string = expander.expandToString( template, null, null );
    assertThat( string, is( "*://*:*/**?X" ) );

    template = Parser.parse( "http://localhost:62142/gateway/cluster/webhdfs/data/v1/tmp/GatewayWebHdfsFuncTest/testBasicHdfsUseCase/dir/file?aG9zdD1sb2NhbGhvc3QmcG9ydD02MjEzOSZvcD1DUkVBVEUmdXNlci5uYW1lPWhkZnM" );
    assertThat( template, notNullValue() );
    assertThat( template.getQuery().get( "aG9zdD1sb2NhbGhvc3QmcG9ydD02MjEzOSZvcD1DUkVBVEUmdXNlci5uYW1lPWhkZnM" ), notNullValue() );
    string = expander.expandToString( template, null, null );
    assertThat( string, is( "http://localhost:62142/gateway/cluster/webhdfs/data/v1/tmp/GatewayWebHdfsFuncTest/testBasicHdfsUseCase/dir/file?aG9zdD1sb2NhbGhvc3QmcG9ydD02MjEzOSZvcD1DUkVBVEUmdXNlci5uYW1lPWhkZnM" ) );

    template = Parser.parse( "http://localhost:62142/gateway/cluster/webhdfs/data/v1/tmp/GatewayWebHdfsFuncTest/testBasicHdfsUseCase/dir/file?aG9zdD1sb2NhbGhvc3QmcG9ydD02MjEzOSZvcD1DUkVBVEUmdXNlci5uYW1lPWhkZnM=" );
    assertThat( template, notNullValue() );
    assertThat( template.getQuery().get( "aG9zdD1sb2NhbGhvc3QmcG9ydD02MjEzOSZvcD1DUkVBVEUmdXNlci5uYW1lPWhkZnM" ), notNullValue() );
    string = expander.expandToString( template, null, null );
    assertThat( string, is( "http://localhost:62142/gateway/cluster/webhdfs/data/v1/tmp/GatewayWebHdfsFuncTest/testBasicHdfsUseCase/dir/file?aG9zdD1sb2NhbGhvc3QmcG9ydD02MjEzOSZvcD1DUkVBVEUmdXNlci5uYW1lPWhkZnM" ) );
  }

  @Test
  public void testTemplateWithOnlyAuthority() throws Exception {
    Template template;
    Parser parser = new Parser();

    template = parser.parseTemplate( "test-host:42" );
    assertThat( template.hasScheme(), is( false ) );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "test-host" ) );
    assertThat( template.getPort().getFirstValue().getPattern(), is( "42" ) );
    assertThat( template.toString(), is( "test-host:42" ) );

    template = parser.parseTemplate( "{test-host}:{test-port}" );
    assertThat( template.hasScheme(), is( false ) );
    assertThat( template.getHost().getParamName(), is( "test-host" ) );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPort().getParamName(), is( "test-port" ) );
    assertThat( template.getPort().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.toString(), is( "{test-host=*}:{test-port=*}" ) );
  }

  @Test
  public void testTemplateWithoutAuthority() throws Exception {
    Template template;
    Parser parser = new Parser();

    template = parser.parseTemplate( "test-scheme:/test-path" );
    assertThat( template.hasScheme(), is( true ) );
    assertThat( template.getScheme().getFirstValue().getPattern(), is( "test-scheme" ) );
    assertThat( template.hasAuthority(), is( false ) );
    assertThat( template.getPath().size(), is( 1 ) );
    assertThat( template.getPath().get( 0 ).getFirstValue().getPattern(), is( "test-path" ) );
    assertThat( template.hasQuery(), is( false ) );
    assertThat( template.toString(), is( "test-scheme:/test-path" ) );

    template = parser.parseTemplate( "test-scheme:///test-path" );
    assertThat( template.hasScheme(), is( true ) );
    assertThat( template.getScheme().getFirstValue().getPattern(), is( "test-scheme" ) );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );
    assertThat( template.getPath().size(), is( 1 ) );
    assertThat( template.getPath().get( 0 ).getFirstValue().getPattern(), is( "test-path" ) );
    assertThat( template.hasQuery(), is( false ) );
    assertThat( template.toString(), is( "test-scheme:///test-path" ) );

    template = parser.parseTemplate( "{test-scheme}:/{test-path}" );
    assertThat( template.hasScheme(), is( true ) );
    assertThat( template.getScheme().getParamName(), is( "test-scheme" ) );
    assertThat( template.getScheme().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.hasAuthority(), is( false ) );
    assertThat( template.getPath().size(), is( 1 ) );
    assertThat( template.getPath().get( 0 ).getParamName(), is( "test-path" ) );
    assertThat( template.getPath().get( 0 ).getFirstValue().getPattern(), is( "**" ) );
    assertThat( template.hasQuery(), is( false ) );
    assertThat( template.toString(), is( "{test-scheme=*}:/{test-path=**}" ) );

    template = parser.parseTemplate( "{test-scheme}:///{test-path}" );
    assertThat( template.hasScheme(), is( true ) );
    assertThat( template.getScheme().getParamName(), is( "test-scheme" ) );
    assertThat( template.getScheme().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.hasAuthority(), is( true ) );
    assertThat( template.getUsername(), nullValue() );
    assertThat( template.getPassword(), nullValue() );
    assertThat( template.getHost(), nullValue() );
    assertThat( template.getPort(), nullValue() );
    assertThat( template.getPath().size(), is( 1 ) );
    assertThat( template.getPath().get( 0 ).getParamName(), is( "test-path" ) );
    assertThat( template.getPath().get( 0 ).getFirstValue().getPattern(), is( "**" ) );
    assertThat( template.hasQuery(), is( false ) );
    assertThat( template.toString(), is( "{test-scheme=*}:///{test-path=**}" ) );
  }

  @Test
  public void testAuthorityWildcards() throws Exception {
    Template template;

    template = Parser.parse( "*://*:*/" );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPort().getFirstValue().getPattern(), is( "*" ) );

    template = Parser.parse( "*://**/" );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPort(), nullValue() );

    template = Parser.parse( "*://*/" );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPort(), nullValue() );

    template = Parser.parse( "*://**:**/" );
    assertThat( template.getHost().getFirstValue().getPattern(), is( "*" ) );
    assertThat( template.getPort().getFirstValue().getPattern(), is( "*" ) );
  }

}
