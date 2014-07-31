package org.apache.hadoop.gateway.ssh.commands.connect;

import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.Signal;
import org.apache.sshd.server.SignalListener;

public class TerminalSizeListener implements SignalListener {

  public static class Factory {
    private final Environment environment;

    public Factory(Environment environment) {
      this.environment = environment;
    }

    public TerminalSizeListener getModeSetter(ChannelShell channelShell) {
      TerminalSizeListener setter =  new TerminalSizeListener(environment, channelShell, new TerminalSizeSetter());
      environment.addSignalListener(setter, Signal.WINCH);
      return setter;
    }

  }

  private ChannelShell channelShell;
  private Environment environment;
  private TerminalSizeSetter terminalSizeSetter;

  public TerminalSizeListener(Environment environment, ChannelShell channelShell, TerminalSizeSetter terminalSizeSetter) {
    this.channelShell = channelShell;
    this.environment = environment;
    this.terminalSizeSetter = terminalSizeSetter;
  }

  @Override
  public void signal(Signal signal) {
    terminalSizeSetter.setTerminalSize(channelShell, environment);
  }
}