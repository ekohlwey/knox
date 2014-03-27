package org.apache.hadoop.gateway.ssh;

import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.apache.sshd.common.Factory;
import org.apache.sshd.server.Command;

public class KnoxTunnelShellFactory implements Factory<Command> {

  private final String topologyName;

  public KnoxTunnelShellFactory(String topologyName) {
    this.topologyName = topologyName;
  }
  
  @Override
  public KnoxTunnelShell create() {
    return new KnoxTunnelShell(topologyName);
  }
}
