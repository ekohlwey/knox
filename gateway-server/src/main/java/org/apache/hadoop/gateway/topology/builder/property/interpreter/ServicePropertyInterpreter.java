/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.hadoop.gateway.topology.builder.property.interpreter;

import org.apache.hadoop.gateway.GatewayResources;
import org.apache.hadoop.gateway.i18n.resources.ResourcesFactory;
import org.apache.hadoop.gateway.topology.Service;
import org.apache.hadoop.gateway.topology.Topology;

public class ServicePropertyInterpreter extends AbstractInterpreter {

    private static final String SERVICE_URL = "url";

    private static GatewayResources gatewayResources = ResourcesFactory.get(GatewayResources.class);

    private Topology topology;

    public ServicePropertyInterpreter(Topology topology) {
        if (topology == null) {
            throw new IllegalArgumentException(gatewayResources.topologyIsRequiredError());
        }
        this.topology = topology;
    }

    public void interpret(String token, String value) throws InterpretException {
        int dotPosition = token.indexOf(DOT);
        if (dotPosition == -1) {
            throw new InterpretException(gatewayResources.unsupportedPropertyTokenError(token));
        }
        String serviceRole = token.substring(0, dotPosition);
        if (serviceRole != null && serviceRole.isEmpty()) {
            serviceRole = null;
        }
        String nextToken = token.substring(dotPosition + 1);

        dotPosition = nextToken.indexOf(DOT);
        if (dotPosition == -1) {
            throw new InterpretException(gatewayResources.unsupportedPropertyTokenError(token));
        }
        String serviceName = nextToken.substring(0, dotPosition);
        if (serviceName != null && serviceName.isEmpty()) {
            serviceName = null;
        }
        nextToken = nextToken.substring(dotPosition + 1);

        Service service = topology.getService(serviceRole, serviceName);
        if (service == null) {
            service = new Service();
            service.setName(serviceName);
            service.setRole(serviceRole);
            topology.addService(service);
        }

        if (SERVICE_URL.equalsIgnoreCase(nextToken)) {
            service.setUrl( value );
        } else {
            throw new InterpretException(gatewayResources.unsupportedPropertyTokenError(token));
        }
    }
}
