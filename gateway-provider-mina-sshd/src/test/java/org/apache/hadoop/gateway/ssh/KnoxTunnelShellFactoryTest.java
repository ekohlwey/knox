package org.apache.hadoop.gateway.ssh;

import static org.junit.Assert.assertEquals;

import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.junit.Test;

public class KnoxTunnelShellFactoryTest {

  @Test
  public void testNamePassthrough() {
    SSHConfiguration configuration = new SSHConfiguration();
    KnoxTunnelShellFactory factory = new KnoxTunnelShellFactory("foobar", configuration);
    KnoxTunnelShell command = factory.create();
    assertEquals("foobar", command.getTopologyName());
    assertEquals(configuration, command.getConfiguration());
  }

}
