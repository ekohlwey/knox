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
package org.apache.hadoop.gateway.filter.rewrite.i18n;

import org.apache.hadoop.gateway.i18n.messages.Message;
import org.apache.hadoop.gateway.i18n.messages.MessageLevel;
import org.apache.hadoop.gateway.i18n.messages.Messages;
import org.apache.hadoop.gateway.i18n.messages.StackTrace;

@Messages(logger="org.apache.hadoop.gateway")
public interface UrlRewriteMessages {

  @Message( level = MessageLevel.DEBUG, text = "Failed to parse value as URL: {0}" )
  void failedToParseValueForUrlRewrite( String value );

  @Message( level = MessageLevel.ERROR, text = "Failed to write the rules descriptor: {0}" )
  void failedToWriteRulesDescriptor( @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.DEBUG, text = "Failed to filter attribute {0}: {1}" )
  void failedToFilterAttribute( String attributeName, @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to load rewrite rules descriptor: {0}" )
  void failedToLoadRewriteRulesDescriptor( @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to initialize rewrite rules: {0}" )
  void failedToInitializeRewriteRules( @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to initialize rewrite functions: {0}" )
  void failedToInitializeRewriteFunctions( @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to destroy rewrite rule processor: {0}" )
  void failedToDestroyRewriteRuleProcessor( @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to destroy rewrite function processor: {0}" )
  void failedToDestroyRewriteFunctionProcessor( @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to rewrite URL: {0}" )
  void failedToRewriteUrl( @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to filter value {0}: {1}" )
  void failedToFilterValue( String value, @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to filter field name {0}: {1}" )
  void failedToFilterFieldName( String fieldName, @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to function {0}: {1}" )
  void failedToInvokeRewriteFunction( String functionName, @StackTrace( level = MessageLevel.DEBUG ) Exception e );

  @Message( level = MessageLevel.ERROR, text = "Failed to find values by parameter name {0}: {1}" )
  void failedToFindValuesByParameter( String parameterName, @StackTrace( level = MessageLevel.DEBUG ) Exception e );

}
