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
package org.apache.hadoop.gateway.util;

import org.junit.Test;

import junit.framework.TestCase;

public class IpAddressValidatorTest extends TestCase {
  String test = "127.0.0.1,193.*,192.168.1.*";
  String testWeirdConfig = ",127.0.0.1,,193.*,192.168.1.*,29*";
  String testNullConfig = null;
  
  @Test
  public void testExplicitIpAddress() throws Exception {
    IpAddressValidator ipv = new IpAddressValidator(test);
    
    assertTrue("Should have validated 127.0.0.1", ipv.validateIpAddress("127.0.0.1"));
    assertFalse("Should not have validated 127.0.0.2", ipv.validateIpAddress("127.0.0.2"));

    ipv = new IpAddressValidator(testWeirdConfig);
    
    assertTrue("Should have validated 127.0.0.1", ipv.validateIpAddress("127.0.0.1"));
    assertFalse("Should not have validated 127.0.0.2", ipv.validateIpAddress("127.0.0.2"));
  }
  
  @Test
  public void testNullConfig() throws Exception {
    IpAddressValidator ipv = new IpAddressValidator(testNullConfig);

    // null config indicatest that all IPs are accepted
    assertTrue("Should have validated 127.0.0.1", ipv.validateIpAddress("127.0.0.1"));
  }
  
  @Test
  public void testNullRemoteIP() throws Exception {
    IpAddressValidator ipv = new IpAddressValidator(testNullConfig);

    assertFalse("Should not have validated null", ipv.validateIpAddress(null));
  }

  @Test
  public void testWildcardIpAddress() throws Exception {
    IpAddressValidator ipv = new IpAddressValidator(test);
    
    assertTrue("Should have validated 192.168.1.1", ipv.validateIpAddress("192.168.1.1"));
    assertFalse("Should not have validated 192.168.2.1", ipv.validateIpAddress("192.168.2.1"));

    assertTrue("Should have validated 193.168.1.1", ipv.validateIpAddress("193.168.1.1"));
    assertFalse("Should not have validated 194.168.2.1", ipv.validateIpAddress("194.168.2.1"));

    ipv = new IpAddressValidator(testWeirdConfig);
    
    assertTrue("Should have validated 293.168.1.1", ipv.validateIpAddress("293.168.1.1"));
  }

}
