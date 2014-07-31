package org.apache.hadoop.gateway.ssh.commands.connect;

import java.util.Map;
import java.util.Map.Entry;

import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.server.Environment;

public class ShellModesAndEnvironmentSetter {

  public void setModesAndEnvironment(ChannelShell channelShell,
      Environment environment) {
    channelShell.setPtyModes(environment.getPtyModes());
    Map<String, String> environmentMap = environment.getEnv();
    String type = environmentMap.get(Environment.ENV_TERM);
    if (type != null) {
      channelShell.setPtyType(type);
    }
    for (Entry<String, String> entry : environmentMap.entrySet()) {
      channelShell.setEnv(entry.getKey(), entry.getValue());
    }
  }

}
