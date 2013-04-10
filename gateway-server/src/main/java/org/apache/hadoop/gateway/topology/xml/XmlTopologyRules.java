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

import org.apache.commons.digester3.binder.AbstractRulesModule;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.ProviderParam;
import org.apache.hadoop.gateway.topology.Service;
import org.apache.hadoop.gateway.topology.Topology;

public class XmlTopologyRules extends AbstractRulesModule {

  private static final String ROOT_TAG = "topology";
  private static final String NAME_TAG = "name";
  private static final String VERSION_TAG = "version";
  private static final String SERVICE_TAG = "service";
  private static final String ROLE_TAG = "role";
  private static final String URL_TAG = "url";
  private static final String PROVIDER_TAG = "gateway/provider";
  private static final String ENABLED_TAG = "enabled";
  private static final String PARAM_TAG = "param";
  private static final String VALUE_TAG = "value";

  @Override
  protected void configure() {
    forPattern( ROOT_TAG ).createObject().ofType( Topology.class );
    forPattern( ROOT_TAG + "/" + NAME_TAG ).setBeanProperty();
    forPattern( ROOT_TAG + "/" + VERSION_TAG ).setBeanProperty();
    forPattern( ROOT_TAG + "/" + SERVICE_TAG ).createObject().ofType( Service.class ).then().setNext( "addService" );
    forPattern( ROOT_TAG + "/" + SERVICE_TAG + "/" + ROLE_TAG ).setBeanProperty();
    forPattern( ROOT_TAG + "/" + SERVICE_TAG + "/" + URL_TAG ).setBeanProperty();
    forPattern( ROOT_TAG + "/" + PROVIDER_TAG ).createObject().ofType( Provider.class ).then().setNext( "addProvider" );
    forPattern( ROOT_TAG + "/" + PROVIDER_TAG + "/" + ROLE_TAG ).setBeanProperty();
    forPattern( ROOT_TAG + "/" + PROVIDER_TAG + "/" + ENABLED_TAG ).setBeanProperty();
    forPattern( ROOT_TAG + "/" + PROVIDER_TAG + "/" + NAME_TAG ).setBeanProperty();
    forPattern( ROOT_TAG + "/" + PROVIDER_TAG + "/" + PARAM_TAG ).createObject().ofType( ProviderParam.class ).then().setNext( "addParam" );
    forPattern( ROOT_TAG + "/" + PROVIDER_TAG + "/" + PARAM_TAG + "/" + NAME_TAG ).setBeanProperty();
    forPattern( ROOT_TAG + "/" + PROVIDER_TAG + "/" + PARAM_TAG + "/" + VALUE_TAG ).setBeanProperty();
  }

}
