package org.apache.hadoop.gateway.ssh.commands;

import static java.nio.charset.Charset.forName;
import static java.util.Arrays.asList;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintWriter;
import java.io.SequenceInputStream;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.io.input.ReaderInputStream;
import org.apache.commons.io.input.TeeInputStream;
import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditManager;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.agent.unix.AgentClient;
import org.apache.sshd.agent.unix.AgentServer;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.UserAuthPublicKey;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.KeyPairProvider;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.RuntimeSshException;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.util.NoCloseInputStream;
import org.apache.sshd.common.util.NoCloseOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConnectSSHAction extends SSHAction {

  public static class SSHConnector {

    private static final Logger LOG = LoggerFactory
        .getLogger(SSHConnector.class);

    private final String connectAsUser;
    private final TerminalAuditManager auditManager;
    private final KnoxTunnelShell originatingShell;
    private final SSHConfiguration sshConfiguration;

    public SSHConnector(String connectAsUser,
        SSHConfiguration sshConfiguration, KnoxTunnelShell originatingShell) {
      this(connectAsUser, sshConfiguration, TerminalAuditManager.get(),
          originatingShell);
    }

    public SSHConnector(String connectAsUser,
        SSHConfiguration sshConfiguration, TerminalAuditManager auditManager,
        KnoxTunnelShell originatingShell) {
      this.connectAsUser = connectAsUser;
      this.auditManager = auditManager;
      this.originatingShell = originatingShell;
      this.sshConfiguration = sshConfiguration;
    }

    public int connectSSH(String sudoToUser, String host, int port,
        BufferedReader inputStream, OutputStream outputStream,
        OutputStream error) {
      ChannelShell channelShell = null;
      Integer exit = 0;
      InputStream tee = null;
      SequenceInputStream sudoingInputStream;
      ClientSession session = null;
      try {
        SshClient client = SshClient.setUpDefaultClient();
        client.setKeyPairProvider(new FileKeyPairProvider(
            new String[] { sshConfiguration.getKnoxKeyfile() }));
        client.setUserAuthFactories(Arrays.<NamedFactory<UserAuth>>asList(new UserAuthPublicKey.Factory()));
        client.start();
        try {
          ConnectFuture future = client.connect(connectAsUser, host, port);
          if(!future.await(sshConfiguration.getTunnelConnectTimeout())){
            if (LOG.isInfoEnabled()) {
              LOG.info("Was unable to connect to server: " + host + ":" + port
                  + "  connection timed out.", future.getException());
            }
            PrintWriter errorOut = new PrintWriter(new NoCloseOutputStream(
                error));
            errorOut.println("Failed to connect to " + host + ":" + port);
            errorOut.close();
            error.flush();
            return SSH_ERROR_CODE;
          }
          if (!future.isConnected()) {
            if (LOG.isInfoEnabled()) {
              LOG.info("Was unable to connect to server: " + host + ":" + port
                  + "  connection failed.", future.getException());
            }
            PrintWriter errorOut = new PrintWriter(new NoCloseOutputStream(
                error));
            errorOut.println("Failed to connect to " + host + ":" + port);
            errorOut.close();
            error.flush();
            return SSH_ERROR_CODE;
          }

          session = future.getSession();
          session.auth().await(sshConfiguration.getTunnelConnectTimeout());
        } catch (IOException e) {
          LOG.error("Unable to connect to Knox cluster server.", e);
          return SSH_ERROR_CODE;
        } catch (InterruptedException e) {
          LOG.error(
              "Unexpected interruption connecting to Knox cluster server.", e);
          Thread.currentThread().interrupt();
          return SSH_ERROR_CODE;
        }

        try {
          channelShell = session.createShellChannel();
        } catch (IOException e) {
          LOG.error("Unable to create remote shell on Knox cluster server.", e);
          return SSH_ERROR_CODE;
        }
        InputStream shellStream = new NoCloseInputStream(new ReaderInputStream(
            inputStream));
        PipedInputStream loggingInputStream = new PipedInputStream();
        PipedOutputStream loggingOutputStream;
        try {
          loggingOutputStream = new PipedOutputStream(loggingInputStream);
        } catch (IOException e) {
          LOG.error("Unable to fork input for remote server logging.", e);
          return SSH_ERROR_CODE;
        }
        tee = new TeeInputStream(shellStream, loggingOutputStream, true);
        auditManager.auditStream(loggingInputStream, host + ":" + port,
            sudoToUser, originatingShell);
        String sudoCommand = sshConfiguration.getLoginCommand();
        String sudoCommandWithUser = sudoCommand.replace("{0}", sudoToUser);
        sudoingInputStream = new SequenceInputStream(new ByteArrayInputStream(
            sudoCommandWithUser.getBytes(forName("UTF-8"))), tee);
        channelShell.setIn(sudoingInputStream);
        channelShell.setOut(new NoCloseOutputStream(outputStream));
        channelShell.setErr(new NoCloseOutputStream(error));
        try{
          channelShell.open().await(sshConfiguration.getTunnelConnectTimeout());
        } catch (InterruptedException e) {
          LOG.error(
              "Unexpected interruption during logged session to remote Knox cluster server.",
              e);
          Thread.currentThread().interrupt();
          return SSH_ERROR_CODE;
        } catch (IOException e) {
          LOG.error(
              "Unexpected IO exception during logged session to remote Knox cluster server.",
              e);
          return SSH_ERROR_CODE;
        }
        channelShell.waitFor(ClientChannel.CLOSED,
            sshConfiguration.getTunnelConnectTimeout());
        exit = channelShell.getExitStatus();
      } finally {
        if (channelShell != null) {
          channelShell.close(true);
        }
        if (tee != null) {
          try {
            tee.close();
          } catch (IOException e) {
            LOG.error("Unable to close logging tee. "
                + "Audit information may have been lost.", e);
          }
        }
      }
      //exit is an Integer that can be null, the auto-boxing could cause an NPE
      return exit == null ? -1 : exit;
    }
  }

  public static int SSH_ERROR_CODE = 255;
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
