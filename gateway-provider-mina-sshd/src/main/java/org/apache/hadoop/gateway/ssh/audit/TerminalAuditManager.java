package org.apache.hadoop.gateway.ssh.audit;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.concurrent.ArrayBlockingQueue;

import org.apache.hadoop.gateway.ssh.ProviderConfigurer;
import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;

public class TerminalAuditManager {

  private static TerminalAuditManager INSTANCE;
  private static final Object lock = new Object();

  public static TerminalAuditManager get(SSHConfiguration sshConfiguration) {
    synchronized (lock) {
      if(INSTANCE == null) {
        INSTANCE = new TerminalAuditManager(sshConfiguration);
      }
    }
    return INSTANCE;
  }

  private final TerminalActionAuditRecorder auditor;
  private final ArrayBlockingQueue<TerminalAuditWork> terminalWorkQueue;
  private final TerminalAuditThread auditThread;

  private TerminalAuditManager(SSHConfiguration sshConfiguration) {
    this(new TerminalActionAuditRecorder(new TerminalErrorHandler()),
        sshConfiguration.getQueueSize());
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
      KnoxTunnelShell originatingShell, String encoding) {
    terminalWorkQueue.add(new TerminalAuditWork(resource, user, in,
        originatingShell, encoding));
  }

  public void auditMessage(String message, String resource, String user,
                           KnoxTunnelShell originatingShell) {
    terminalWorkQueue.add(new TerminalAuditWork(resource, user,
        new ByteArrayInputStream(message.getBytes(Charset.forName("UTF-8"))), originatingShell, "UTF-8"));
  }

}
