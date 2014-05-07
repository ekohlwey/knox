package org.apache.hadoop.gateway.ssh.commands;

import static org.apache.hadoop.gateway.ssh.commands.SSHConstants.SSH_ERROR_CODE;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hadoop.gateway.i18n.messages.MessagesFactory;
import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.SshGatewayMessages;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.util.NoCloseOutputStream;

public class ConnectSSHAction extends SSHAction {

  private static final SshGatewayMessages LOG = MessagesFactory.get(SshGatewayMessages.class);
  private Matcher matcher = Pattern.compile(
      "\\s*([a-zA-Z0-9.]+)(?::([0-9]+))?\\s*$").matcher("");
  private SSHConnector sshConnector;
  private final String sudoToUser;

  public ConnectSSHAction(String sudoToUser,
                          SSHConnector sshConnector) {
    super("connect", "<host>[:<port>]",
        "Connect to a server within the Knox cluster.");
    this.sudoToUser = sudoToUser;
    this.sshConnector = sshConnector;
  }

  public ConnectSSHAction(String sudoToUser,
                          SSHConfiguration sshConfiguration,
                          KnoxTunnelShell tunnelShell) {
    this(sudoToUser, new SSHConnector(sshConfiguration, tunnelShell));
  }

  @Override
  public int handleCommand(String command, String commandLine,
                           InputStream commandStream, OutputStream outputStream, OutputStream error)
      throws IOException {
    matcher.reset(commandLine);
    if (matcher.matches()) {
      String host = matcher.group(1);
      String portString = matcher.group(2);
      int port;
      if (portString != null) {
        port = Integer.parseInt(portString);
      } else {
        port = 22;
      }
      try {
        return sshConnector
            .connectSSH(sudoToUser, host, port, commandStream, outputStream,
                error);
      } catch (RuntimeSshException e) {
        LOG.failedConnectingToRemote(host + ":" + port, e);
        PrintWriter errorWriter = new PrintWriter(
            new NoCloseOutputStream(error));
        errorWriter.println("Unable to connect to " + host + " on port "
            + portString);
        errorWriter.close();
        error.flush();
        return SSH_ERROR_CODE;
      }
    } else {
      PrintWriter errorWriter = new PrintWriter(new NoCloseOutputStream(error));
      errorWriter.println("Invalid argument: " + commandLine);
      errorWriter.println("please use a hostname of the form <host>[:<port>]");
      errorWriter.close();
      error.flush();
      return SSH_ERROR_CODE;
    }
  }

}
