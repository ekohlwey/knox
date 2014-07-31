package org.apache.hadoop.gateway.ssh.audit;

import java.io.IOException;

import org.apache.hadoop.gateway.audit.api.Action;
import org.apache.hadoop.gateway.audit.api.ActionOutcome;
import org.apache.hadoop.gateway.audit.api.AuditServiceFactory;
import org.apache.hadoop.gateway.audit.api.Auditor;
import org.apache.hadoop.gateway.audit.api.ResourceType;
import org.apache.hadoop.gateway.audit.log4j.audit.AuditConstants;
import org.apache.hadoop.gateway.ssh.util.LineReaderInputStream;

import com.google.common.io.NullOutputStream;

public class TerminalActionAuditRecorder {

  private final TerminalErrorHandler handler;
  private final Auditor auditor;

  public TerminalActionAuditRecorder(TerminalErrorHandler handler) {
    this(handler, AuditServiceFactory.getAuditService().getAuditor(
        AuditConstants.DEFAULT_AUDITOR_NAME, AuditConstants.KNOX_SERVICE_NAME,
        AuditConstants.KNOX_COMPONENT_NAME));
  }

  TerminalActionAuditRecorder(TerminalErrorHandler handler, Auditor auditor) {
    this.handler = handler;
    this.auditor = auditor;
  }

  public void auditWork(TerminalAuditWork work) {
    // Buffered Reader does not work here, the stream buffers and does not
    // output
    LineReaderInputStream lineReaderInputStream = new LineReaderInputStream(
        work.getStream(), new NullOutputStream(), work.getEncoding());
    try {
      String line;
      do {
        try {
          line = lineReaderInputStream.readLine();
        } catch (IOException e) {
          handler.handleError(e, work.getOriginatingShell());
          return;
        }
        String user = work.getUser();
        String resource = work.getResource();
        if (line != null) {
          auditor.audit(Action.ACCESS, user + "@" + resource + ":" + line,
              ResourceType.TOPOLOGY, ActionOutcome.UNAVAILABLE);
        }
      } while (line != null);
    } finally {
      try {
        lineReaderInputStream.close();
      } catch (IOException e) {
        handler.handleError(e, work.getOriginatingShell());
        return;
      }
    }
  }
}