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
package org.apache.hadoop.gateway;

import org.apache.hadoop.gateway.i18n.resources.Resource;
import org.apache.hadoop.gateway.i18n.resources.Resources;

/**
 *
 */
@Resources
public interface GatewayResources {

  @Resource( text="Apache Hadoop Gateway {0} ({1})" )
  String gatewayVersionMessage( String version, String hash );

  @Resource( text="Apache Hadoop Gateway" )
  String gatewayServletInfo();

  @Resource( text="Service connectivity error." )
  String dispatchConnectionError();

  @Resource( text="Display command line help." )
  String helpMessage();

  @Resource( text="This parameter causes the server to exit before starting to service requests. This is typically used with the -persist-master parameter." )
  String nostartHelpMessage();

  @Resource( text="This parameter causes the provider master secret to be persisted. This prevents the server from prompting for a master secret on subsequent starts." )
  String persistmasterHelpMessage();

  @Resource( text="Display server version information." )
  String versionHelpMessage();

  @Resource( text="Topology is required." )
  String topologyIsRequiredError();

  @Resource( text="Provider is required." )
  String providerIsRequiredError();

  @Resource( text="Unsupported property's token: {0}" )
  String unsupportedPropertyTokenError(String token);

  @Resource( text="Failed to build topology: wrong data format." )
  String wrongTopologyDataFormatError();

  @Resource( text="Provider parameter name is required." )
  String providerParameterNameIsRequiredError();

  @Resource( text="Provider parameter value is required." )
  String providerParameterValueIsRequiredError();
}
