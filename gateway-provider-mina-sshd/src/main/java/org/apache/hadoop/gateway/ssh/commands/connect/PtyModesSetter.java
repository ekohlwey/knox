package org.apache.hadoop.gateway.ssh.commands.connect;

import java.util.Map;

import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.server.Environment;

public class PtyModesSetter {


  public void setPtyModesFromEnvrionment(ChannelShell channelShell, Environment environment) {
    channelShell.setPtyModes(environment.getPtyModes());
    Map<String, String> environmentMap = environment.getEnv();
    String type = environmentMap.get(Environment.ENV_TERM);
    if (type != null) {
      channelShell.setPtyType(type);
    }
  }

}
