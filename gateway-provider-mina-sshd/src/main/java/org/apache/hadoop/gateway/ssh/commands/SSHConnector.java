package org.apache.hadoop.gateway.ssh.commands;

import static java.nio.charset.Charset.forName;
import static org.apache.hadoop.gateway.ssh.commands.SSHConstants.SSH_ERROR_CODE;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintWriter;
import java.io.SequenceInputStream;
import java.util.Arrays;
import java.util.Map;

import org.apache.commons.io.input.TeeInputStream;
import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditManager;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.UserAuthPublicKey;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PtyMode;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.util.NoCloseInputStream;
import org.apache.sshd.common.util.NoCloseOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSHConnector {

  private static final Logger LOG = LoggerFactory.getLogger(SSHConnector.class);

  public static class SshClientBuilder {

    private final SSHConfiguration sshConfiguration;

    public SshClientBuilder(SSHConfiguration sshConfiguration) {
      this.sshConfiguration = sshConfiguration;
    }

    public SshClient build() {
      SshClient client = SshClient.setUpDefaultClient();
      client.setKeyPairProvider(new FileKeyPairProvider(
          new String[]{sshConfiguration.getKnoxKeyfile()}));
      client.setUserAuthFactories(Arrays
          .<NamedFactory<UserAuth>>asList(new UserAuthPublicKey.Factory()));
      return client;
    }
  }

  public static class SshClientConnectTimeoutException extends Exception {
    public SshClientConnectTimeoutException(Throwable exception) {
      super(exception);
    }
  }

  public static class SshClientConnectionFailedException extends Exception {
    public SshClientConnectionFailedException(Throwable exception) {
      super(exception);
    }
  }

  public static class SshClientConnectionUnauthorizedException extends
      Exception {
    public SshClientConnectionUnauthorizedException() {
    }

    public SshClientConnectionUnauthorizedException(String message,
                                                    SshException e) {
      super(message, e);
    }
  }

  public static class SshClientConnector {

    private final SSHConfiguration sshConfiguration;

    public SshClientConnector(SSHConfiguration sshConfiguration) {
      this.sshConfiguration = sshConfiguration;
    }

    public ClientSession connect(SshClient sshClient, String host, Integer port)
        throws IOException, InterruptedException,
        SshClientConnectTimeoutException, SshClientConnectionFailedException,
        SshClientConnectionUnauthorizedException {

      ConnectFuture connectFuture =
          sshClient.connect(sshConfiguration.getKnoxLoginUser(), host, port);
      if (!connectFuture.await(sshConfiguration.getTunnelConnectTimeout())) {
        throw new SshClientConnectTimeoutException(
            connectFuture.getException());
      }
      if (!connectFuture.isConnected()) {
        throw new SshClientConnectionFailedException(
            connectFuture.getException());
      }
      ClientSession session = connectFuture.getSession();
      AuthFuture auth = session.auth();
      if (!auth.await(sshConfiguration.getTunnelConnectTimeout())) {
        throw new SshClientConnectTimeoutException(auth.getException());
      }
      try {
        auth.verify();
      } catch (SshException e) {
        throw new SshClientConnectionUnauthorizedException(e.getMessage(), e);
      }
      return session;
    }
  }

  public static class SudoCommandStreamBuilder {

    private final SSHConfiguration sshConfiguration;

    public SudoCommandStreamBuilder(SSHConfiguration sshConfiguration) {
      this.sshConfiguration = sshConfiguration;
    }

    public InputStream buildSudoCommand(String sudoToUser, InputStream command,
                                        PipedInputStream loggingInputStream)
        throws IOException {
      PipedOutputStream loggingOutputStream =
          new PipedOutputStream(loggingInputStream);
      InputStream tee =
          new TeeInputStream(command, loggingOutputStream, true);

      String sudoCommand = sshConfiguration.getLoginCommand();
      String sudoCommandWithUser = sudoCommand.replace("{0}", sudoToUser);
      return new SequenceInputStream(new ByteArrayInputStream(
          sudoCommandWithUser.getBytes(forName("UTF-8"))), tee);
    }
  }

  public static class ChannelShellPtyModesSetter {

    public void setupSensiblePtyModes(ChannelShell channelShell)
        throws IOException {
      channelShell.setupSensibleDefaultPty();
      Map<PtyMode, Integer> ptyModes = channelShell.getPtyModes();
      ptyModes.put(PtyMode.ECHO, 1); //make sure input is still echoing
      ptyModes.put(PtyMode.ICANON, 1); //line editing mode
      ptyModes.put(PtyMode.VEOL, 13); //^M carriage return for EOL
      ptyModes.put(PtyMode.VEOL2, 13); //^M carriage return for EOL
      ptyModes.put(PtyMode.ICRNL, 1); //Carriage Return -> Line Feed conversion
    }
  }

  public static class SshCommandSender {

    private final SSHConfiguration sshConfiguration;
    private final ChannelShellPtyModesSetter channelShellPtyModesSetter;

    public SshCommandSender(SSHConfiguration sshConfiguration,
                            ChannelShellPtyModesSetter channelShellPtyModesSetter) {
      this.sshConfiguration = sshConfiguration;
      this.channelShellPtyModesSetter = channelShellPtyModesSetter;
    }

    /**
     * @return Exit status
     */
    public Integer sendCommand(ClientSession session,
                               InputStream commandInputStream,
                               OutputStream stdOut, OutputStream stdErr)
        throws IOException, InterruptedException,
        SshClientConnectionFailedException {
      ChannelShell channelShell = null;
      try {
        channelShell = session.createShellChannel();
        channelShellPtyModesSetter.setupSensiblePtyModes(channelShell);

        channelShell.setIn(new NoCloseInputStream(commandInputStream));
        channelShell.setOut(new NoCloseOutputStream(stdOut));
        channelShell.setErr(new NoCloseOutputStream(stdErr));
        OpenFuture openFuture = channelShell.open();
        boolean channelOpen =
            openFuture.await(sshConfiguration.getTunnelConnectTimeout());
        if (!channelOpen) {
          throw new SshClientConnectionFailedException(
              openFuture.getException());
        }
        boolean closed = false;
        while(!closed) {
          int status = channelShell.waitFor(ClientChannel.CLOSED, sshConfiguration.getTunnelConnectTimeout());
          closed = (status & ClientChannel.CLOSED) != 0; //closed
          if(!closed) {
            //redo these to keep the environment
            channelShellPtyModesSetter.setupSensiblePtyModes(channelShell);
          }
        }
        return channelShell.getExitStatus();
      } finally {
        if (channelShell != null) {
          channelShell.close(true);
        }
      }
    }
  }

  static void printErrorMessage(String errMessage, OutputStream error,
                                Throwable cause) {
    if (LOG.isInfoEnabled()) {
      LOG.info(errMessage, cause);
    }
    PrintWriter errorOut = new PrintWriter(new NoCloseOutputStream(error));
    errorOut.println(errMessage);
    errorOut.close();
    try {
      error.flush();
    } catch (IOException e) {
      LOG.error("Exception occurred flushing Error Outputstream");
    }
  }

  private final TerminalAuditManager auditManager;
  private final KnoxTunnelShell originatingShell;
  private final SshClientBuilder sshClientBuilder;
  private final SshClientConnector sshClientConnector;
  private final SudoCommandStreamBuilder sudoCommandStreamBuilder;
  private final SshCommandSender sshCommandSender;

  public SSHConnector(SSHConfiguration sshConfiguration,
                      KnoxTunnelShell originatingShell) {
    this(sshConfiguration, TerminalAuditManager.get(sshConfiguration),
        originatingShell, new ChannelShellPtyModesSetter());
  }

  SSHConnector(SSHConfiguration sshConfiguration,
                      TerminalAuditManager auditManager,
                      KnoxTunnelShell originatingShell,
                      ChannelShellPtyModesSetter channelShellPtyModesSetter) {
    this(auditManager, originatingShell, new SshClientBuilder(sshConfiguration),
        new SshClientConnector(sshConfiguration),
        new SudoCommandStreamBuilder(sshConfiguration),
        new SshCommandSender(sshConfiguration, channelShellPtyModesSetter));
  }

  SSHConnector(TerminalAuditManager auditManager,
               KnoxTunnelShell originatingShell,
               SshClientBuilder sshClientBuilder,
               SshClientConnector sshClientConnector,
               SudoCommandStreamBuilder sudoCommandStreamBuilder,
               SshCommandSender sshCommandSender) {
    this.auditManager = auditManager;
    this.originatingShell = originatingShell;
    this.sshClientBuilder = sshClientBuilder;
    this.sshClientConnector = sshClientConnector;
    this.sudoCommandStreamBuilder = sudoCommandStreamBuilder;
    this.sshCommandSender = sshCommandSender;
  }

  public int connectSSH(String sudoToUser, String host, int port,
                        InputStream commandStream, OutputStream outputStream,
                        OutputStream error) {
    Integer exit = 0;
    SshClient sshClient = null;
    ClientSession session = null;
    InputStream sudoingInputStream = null;
    try {
      sshClient = sshClientBuilder.build();
      sshClient.start();

      session = sshClientConnector.connect(sshClient, host, port);

      PipedInputStream loggingInputStream = new PipedInputStream();
      sudoingInputStream = sudoCommandStreamBuilder
          .buildSudoCommand(sudoToUser, commandStream, loggingInputStream);

      auditManager.auditMessage("Logged in", host + ":" + port, sudoToUser,
          originatingShell);
      auditManager
          .auditStream(loggingInputStream, host + ":" + port, sudoToUser,
              originatingShell);

      exit = sshCommandSender
          .sendCommand(session, sudoingInputStream, outputStream, error);
      auditManager.auditMessage("Logged out", host + ":" + port, sudoToUser,
          originatingShell);
    } catch (SshClientConnectTimeoutException e) {
      printErrorMessage("Failed to connect to " + host + ":" + port +
          " connection timed out.", error, e.getCause());
      return SSH_ERROR_CODE;
    } catch (SshClientConnectionFailedException e) {
      printErrorMessage(
          "Was unable to connect to server: " + host + ":" + port +
              "  connection failed.", error, e.getCause());
      return SSH_ERROR_CODE;
    } catch (SshClientConnectionUnauthorizedException e) {
      printErrorMessage("Failed to connect to " + host + ":" + port +
          " User[" + sudoToUser + "] connection unauthorized.", error,
          e.getCause());
      return SSH_ERROR_CODE;
    } catch (IOException e) {
      LOG.error("Unable to connect to Knox cluster server.", e);
      return SSH_ERROR_CODE;
    } catch (InterruptedException e) {
      LOG.error("Unexpected interruption connecting to Knox cluster server.",
          e);
      Thread.currentThread().interrupt();
      return SSH_ERROR_CODE;
    } finally {
      if (sudoingInputStream != null) {
        try {
          sudoingInputStream.close();
        } catch (IOException e) {
          LOG.error("Unable to close logging tee. " +
              "Audit information may have been lost.", e);
        }
      }
      if (session != null) {
        session.close(true);
      }
      if (sshClient != null) {
        sshClient.stop();
      }
    }
    //exit is an Integer that can be null, the auto-boxing could cause an NPE
    return exit == null ? SSH_ERROR_CODE : exit;
  }

}