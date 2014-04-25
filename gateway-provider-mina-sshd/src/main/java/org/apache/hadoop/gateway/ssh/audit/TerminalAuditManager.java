package org.apache.hadoop.gateway.ssh.audit;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.ArrayBlockingQueue;

import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;

public class TerminalAuditManager {

  private static final TerminalAuditManager INSTANCE = new TerminalAuditManager();

  public static TerminalAuditManager get() {
    return INSTANCE;
  }

  private TerminalErrorHandler errorHandler = new TerminalErrorHandler();
  private TerminalActionAuditRecorder auditor = new TerminalActionAuditRecorder(
      errorHandler);
  private ArrayBlockingQueue<TerminalAuditWork> terminalWorkQueue = new ArrayBlockingQueue<TerminalAuditWork>(
      1024);
  private TerminalAuditThread auditThread = new TerminalAuditThread(
      terminalWorkQueue, auditor);

  private TerminalAuditManager() {
    auditThread.start();
    Runtime.getRuntime().addShutdownHook(new Thread() {
      @Override
      public void run() {
        auditThread.close();
      }
    });

  }

  public void auditStream(InputStream in, String resource, String user,
      KnoxTunnelShell originatingShell) {
    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
    terminalWorkQueue.add(new TerminalAuditWork(resource, user, reader,
        originatingShell));
  }

}
