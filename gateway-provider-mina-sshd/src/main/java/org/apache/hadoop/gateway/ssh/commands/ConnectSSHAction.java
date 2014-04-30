package org.apache.hadoop.gateway.ssh.commands;

import static org.apache.hadoop.gateway.ssh.commands.SSHConstants.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.util.NoCloseOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConnectSSHAction extends SSHAction {

  private static final Logger LOG = LoggerFactory.getLogger(SSHAction.class);
  private Matcher matcher = Pattern.compile(
      "\\s*([a-zA-Z0-9.]+)(?::([0-9]+))?\\s*$").matcher("");
  private SSHConnector sshConnector;
  private final String sudoToUser;

  public ConnectSSHAction(String username, SSHConfiguration sshConfiguration,
      SSHConnector sshConnector) {
    super("connect", "<host>[:<port>]",
        "Connect to a server within the Knox cluster.");
    this.sudoToUser = username;
    this.sshConnector = sshConnector;
  }

  public ConnectSSHAction(String username, SSHConfiguration sshConfiguration,
      KnoxTunnelShell tunnelShell) {
    this(username, sshConfiguration, new SSHConnector(username,
        sshConfiguration, tunnelShell));
  }

  @Override
  public int handleCommand(String command, String commandLine,
      BufferedReader inputStream, OutputStream outputStream, OutputStream error)
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
        return sshConnector.connectSSH(sudoToUser, host, port, inputStream,
            outputStream, error);
      } catch (RuntimeSshException e) {
        LOG.error("Runtime error when connecting to remote Knox server.");
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
