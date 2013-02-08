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
package org.apache.hadoop.gateway.filter.rewrite.ext;

import org.apache.commons.codec.binary.Base64;
import org.apache.hadoop.gateway.filter.rewrite.spi.UrlRewriteContext;
import org.apache.hadoop.gateway.filter.rewrite.spi.UrlRewriteStepProcessor;
import org.apache.hadoop.gateway.filter.rewrite.spi.UrlRewriteStepStatus;
import org.apache.hadoop.gateway.util.urltemplate.Parser;
import org.apache.hadoop.gateway.util.urltemplate.Template;

public class UrlRewriteActionQueryEncodeProcessor
    implements UrlRewriteStepProcessor<UrlRewriteActionQueryEncodeDescriptor> {

  private static final String ENCODED_PARAMETER_NAME = "_";

  @Override
  public String getType() {
    return UrlRewriteActionQueryEncodeDescriptor.TYPE_NAME;
  }

  @Override
  public void initialize( UrlRewriteActionQueryEncodeDescriptor descriptor ) throws Exception {
  }

  @Override
  public UrlRewriteStepStatus process( UrlRewriteContext context ) throws Exception {
    Template url = context.getCurrentUrl();
    String str = url.toString();
    String path = str;
    String query = null;
    int index = str.indexOf( '?' );
    if( index >= 0 ) {
      path = str.substring( 0, index );
      if( index < str.length() ) {
        query = str.substring( index + 1 );
      }
    }
    if( query != null ) {
      query = Base64.encodeBase64String( query.getBytes( "UTF-8" ) );
      query = removeTrailingEquals( query );
      url = Parser.parse( path + "?" + ENCODED_PARAMETER_NAME +"=" + query );
      context.setCurrentUrl( url );
    }
    return UrlRewriteStepStatus.SUCCESS;
  }

  @Override
  public void destroy() {
  }

  private static String removeTrailingEquals( String s ) {
    int i = s.length()-1;
    while( i > 0 && s.charAt( i ) == '=' ) {
      i--;
    }
    return s.substring( 0, i+1 );
  }

}
