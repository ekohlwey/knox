package org.apache.hadoop.gateway.ssh.audit;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.concurrent.ArrayBlockingQueue;

import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;

public class TerminalAuditManager {

  private static final TerminalAuditManager INSTANCE = new TerminalAuditManager();
  public static final int DEFAULT_QUEUE_SIZE = 1024;

  public static TerminalAuditManager get() {
    return INSTANCE;
  }

  private final TerminalActionAuditRecorder auditor;
  private final ArrayBlockingQueue<TerminalAuditWork> terminalWorkQueue;
  private final TerminalAuditThread auditThread;

  private TerminalAuditManager() {
    this(new TerminalActionAuditRecorder(new TerminalErrorHandler()),
        DEFAULT_QUEUE_SIZE);
  }

  TerminalAuditManager(TerminalActionAuditRecorder terminalActionAuditRecorder, int queueSize) {
    this.auditor = terminalActionAuditRecorder;
    this.terminalWorkQueue = new ArrayBlockingQueue<TerminalAuditWork>(queueSize);
    this.auditThread = new TerminalAuditThread(terminalWorkQueue, auditor);

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
