package org.apache.hadoop.gateway.ssh.commands.connect;

import static org.apache.hadoop.gateway.ssh.commands.SSHReturnCodes.SSH_ERROR_CODE;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditManager;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.common.SshException;
import org.apache.sshd.server.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SSHConnector {

  private static final Logger LOG = LoggerFactory.getLogger(SSHConnector.class);

  public static class SshClientConnectTimeoutException extends Exception {

    private static final long serialVersionUID = 1L;

    public SshClientConnectTimeoutException(Throwable exception) {
      super(exception);
    }
  }

  public static class SshClientConnectionFailedException extends Exception {

    private static final long serialVersionUID = 1L;

    public SshClientConnectionFailedException(Throwable exception) {
      super(exception);
    }
  }

  public static class SshClientConnectionUnauthorizedException extends
      Exception {

    private static final long serialVersionUID = 1L;

    public SshClientConnectionUnauthorizedException() {
    }

    public SshClientConnectionUnauthorizedException(String message,
        SshException e) {
      super(message, e);
    }
  }

  private final TerminalAuditManager auditManager;
  private final KnoxTunnelShell originatingShell;
  private final SSHClientBuilder sshClientBuilder;
  private final SSHClientConnector sshClientConnector;
  private final SudoCommandStreamBuilder sudoCommandStreamBuilder;
  private final SSHCommandSender sshCommandSender;
  private final ErrorMessagePrinter errorPrinter;
  private final OutputStream error;
  private final OutputStream outputStream;
  private final InputStream commandStream;
  private final String sudoToUser;
  private final String encoding;

  public SSHConnector(SSHConfiguration sshConfiguration,
      KnoxTunnelShell originatingShell, Environment environment,
      InputStream commandStream, OutputStream outputStream, OutputStream error,
      String sudoToUser, String encoding) {
    this(TerminalAuditManager.get(sshConfiguration), originatingShell,
        new SSHClientBuilder(sshConfiguration), new SSHClientConnector(
            sshConfiguration), new SudoCommandStreamBuilder(sshConfiguration),
        new SSHCommandSender(sshConfiguration, environment),
        new ErrorMessagePrinter(error), commandStream, outputStream, error,
        sudoToUser, encoding);
  }

  SSHConnector(TerminalAuditManager auditManager,
      KnoxTunnelShell originatingShell, SSHClientBuilder sshClientBuilder,
      SSHClientConnector sshClientConnector,
      SudoCommandStreamBuilder sudoCommandStreamBuilder,
      SSHCommandSender sshCommandSender,
      ErrorMessagePrinter errorPrinter, InputStream commandStream,
      OutputStream outputStream, OutputStream error, String sudoToUser, String encoding) {
    this.auditManager = auditManager;
    this.originatingShell = originatingShell;
    this.sshClientBuilder = sshClientBuilder;
    this.sshClientConnector = sshClientConnector;
    this.sudoCommandStreamBuilder = sudoCommandStreamBuilder;
    this.sshCommandSender = sshCommandSender;
    this.errorPrinter = errorPrinter;
    this.commandStream = commandStream;
    this.outputStream = outputStream;
    this.error = error;
    this.sudoToUser = sudoToUser;
    this.encoding = encoding;
  }

  public int connectSSH(String host, int port) {
    Integer exit = 0;
    SshClient sshClient = null;
    ClientSession session = null;
    InputStream sudoingInputStream = null;
    try {
      sshClient = sshClientBuilder.buildAndStartClient();
      session = sshClientConnector.connect(sshClient, host, port);
      PipedInputStream loggingInputStream = new PipedInputStream();
      sudoingInputStream = sudoCommandStreamBuilder.buildSudoCommand(
          sudoToUser, commandStream, loggingInputStream);
      auditManager.auditMessage("Logged in", host + ":" + port, sudoToUser,
          originatingShell);
      auditManager.auditStream(loggingInputStream, host + ":" + port,
          sudoToUser, originatingShell, encoding);
      exit = sshCommandSender.sendCommands(session, sudoingInputStream,
          outputStream, error);
      auditManager.auditMessage("Logged out", host + ":" + port, sudoToUser,
          originatingShell);
    } catch (SshClientConnectTimeoutException e) {
      String message = "Failed to connect to " + host + ":" + port
          + " connection timed out.";
      if (LOG.isInfoEnabled()) {
        LOG.info(message);
      }
      errorPrinter.printErrorMessage(message);
      return SSH_ERROR_CODE;
    } catch (SshClientConnectionFailedException e) {
      String message = "Was unable to connect to server: " + host + ":" + port
          + "  connection failed.";
      if (LOG.isInfoEnabled()) {
        LOG.info(message);
      }
      errorPrinter.printErrorMessage(message);
      return SSH_ERROR_CODE;
    } catch (SshClientConnectionUnauthorizedException e) {
      String message = "Failed to connect to " + host + ":" + port + " User["
          + sudoToUser + "] connection unauthorized.";
      if (LOG.isInfoEnabled()) {
        LOG.info(message);
      }
      errorPrinter.printErrorMessage(message);
      return SSH_ERROR_CODE;
    } catch (IOException e) {
      LOG.error("Unable to connect to Knox cluster server.", e);
      return SSH_ERROR_CODE;
    } catch (InterruptedException e) {
      LOG.error("Unexpected interruption connecting to Knox cluster server.", e);
      Thread.currentThread().interrupt();
      return SSH_ERROR_CODE;
    } finally {
      if (sudoingInputStream != null) {
        try {
          sudoingInputStream.close();
        } catch (IOException e) {
          LOG.error("Unable to close logging tee. "
              + "Audit information may have been lost.", e);
        }
      }
      if (session != null) {
        session.close(true);
      }
      if (sshClient != null) {
        sshClient.stop();
      }
    }
    // exit is an Integer that can be null, the auto-boxing could cause an NPE
    return exit == null ? SSH_ERROR_CODE : exit;
  }

}