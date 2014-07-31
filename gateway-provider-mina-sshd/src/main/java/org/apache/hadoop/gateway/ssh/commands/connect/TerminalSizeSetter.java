package org.apache.hadoop.gateway.ssh.commands.connect;

import static java.lang.Integer.parseInt;

import java.util.Map;

import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.server.Environment;

public class TerminalSizeSetter {

  public void setTerminalSize(ChannelShell channelShell, Environment environment) {
    Map<String, String> environmentMap = environment.getEnv();
    String columns = environmentMap.get(Environment.ENV_COLUMNS);
    String lines = environmentMap.get(Environment.ENV_LINES);
    if (columns != null) {
      channelShell.setPtyColumns(parseInt(columns));
    }
    if (lines != null) {
      channelShell.setPtyLines(parseInt(lines));
    }
  }

}
