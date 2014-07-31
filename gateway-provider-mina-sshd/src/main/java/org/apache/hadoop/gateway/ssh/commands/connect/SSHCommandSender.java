package org.apache.hadoop.gateway.ssh.commands.connect;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.commands.connect.SSHConnector.SshClientConnectionFailedException;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.util.NoCloseInputStream;
import org.apache.sshd.common.util.NoCloseOutputStream;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.Signal;

public class SSHCommandSender {

  private final SSHConfiguration sshConfiguration;
  private final TerminalSizeListener.Factory channelShellPtyModesSetterFactory;
  private final Environment environment;
  private final ShellModesAndEnvironmentSetter ptyModeSetter;
  private final TerminalSizeSetter terminalSizeSetter;

  public SSHCommandSender(SSHConfiguration sshConfiguration,
      TerminalSizeListener.Factory channelShellPtyModesSetterFactory,
      Environment environment, ShellModesAndEnvironmentSetter ptySetter,
      TerminalSizeSetter terminalSizeSetter) {
    this.sshConfiguration = sshConfiguration;
    this.channelShellPtyModesSetterFactory = channelShellPtyModesSetterFactory;
    this.environment = environment;
    this.ptyModeSetter = ptySetter;
    this.terminalSizeSetter = terminalSizeSetter;
  }

  public SSHCommandSender(SSHConfiguration sshConfiguration,
      Environment environment) {
    this(sshConfiguration, new TerminalSizeListener.Factory(environment), environment,
        new ShellModesAndEnvironmentSetter(), new TerminalSizeSetter());
  }

  /**
   * @return Exit status
   */
  public Integer sendCommands(ClientSession session,
      InputStream commandInputStream, OutputStream stdOut, OutputStream stdErr)
      throws IOException, InterruptedException,
      SshClientConnectionFailedException {
    ChannelShell channelShell = null;
    try {
      channelShell = session.createShellChannel();
      TerminalSizeListener sizeChangeListener = channelShellPtyModesSetterFactory
          .getModeSetter(channelShell);
      ptyModeSetter.setModesAndEnvironment(channelShell, environment);
      terminalSizeSetter.setTerminalSize(channelShell, environment);

      channelShell.setIn(new NoCloseInputStream(commandInputStream));
      channelShell.setOut(new NoCloseOutputStream(stdOut));
      channelShell.setErr(new NoCloseOutputStream(stdErr));
      OpenFuture openFuture = channelShell.open();
      boolean channelOpen = openFuture.await(sshConfiguration
          .getTunnelConnectTimeout());
      if (!channelOpen) {
        throw new SshClientConnectionFailedException(
            openFuture.getException());
      }
      environment.addSignalListener(sizeChangeListener, Signal.WINCH);
      try {
        channelShell.waitFor(ClientChannel.CLOSED, -1);
        return channelShell.getExitStatus();
      } finally {
        environment.removeSignalListener(sizeChangeListener);
      }

    } finally {
      if (channelShell != null) {
        channelShell.close(true);
      }
    }
  }
}