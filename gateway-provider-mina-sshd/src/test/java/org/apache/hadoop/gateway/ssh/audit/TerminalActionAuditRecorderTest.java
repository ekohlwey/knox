package org.apache.hadoop.gateway.ssh.audit;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;

import org.apache.hadoop.gateway.audit.api.Action;
import org.apache.hadoop.gateway.audit.api.ActionOutcome;
import org.apache.hadoop.gateway.audit.api.Auditor;
import org.apache.hadoop.gateway.audit.api.ResourceType;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.easymock.EasyMock;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TerminalActionAuditRecorderTest {

  @Test
  public void testAuditWork() throws Exception {
    String performedWork = "input data";
    String resource = "resource";
    String user = "user";

    TerminalErrorHandler terminalErrorHandlerMock =
        EasyMock.createMock(TerminalErrorHandler.class);
    Auditor auditorMock = EasyMock.createMock(Auditor.class);
    auditorMock.audit(Action.ACCESS, user + "@" + resource + ":" + performedWork,
        ResourceType.TOPOLOGY, ActionOutcome.UNAVAILABLE);
    EasyMock.expectLastCall().once();

    KnoxTunnelShell knoxTunnelShellMock =
        EasyMock.createMock(KnoxTunnelShell.class);

    EasyMock.replay(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock);

    TerminalActionAuditRecorder terminalActionAuditRecorder =
        new TerminalActionAuditRecorder(terminalErrorHandlerMock, auditorMock);

    BufferedReader performedWorkReader =
        new BufferedReader(new StringReader(performedWork));
    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork(resource, user, performedWorkReader,
            knoxTunnelShellMock);

    terminalActionAuditRecorder.auditWork(terminalAuditWork);
    EasyMock.verify(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock);
  }

  @Test
  public void testAuditWorkIOException() throws Exception {
    String resource = "resource";
    String user = "user";

    TerminalErrorHandler terminalErrorHandlerMock =
        EasyMock.createMock(TerminalErrorHandler.class);
    Auditor auditorMock = EasyMock.createMock(Auditor.class);
    KnoxTunnelShell knoxTunnelShellMock =
        EasyMock.createMock(KnoxTunnelShell.class);
    BufferedReader bufferedReaderMock =
        EasyMock.createMock(BufferedReader.class);

    IOException ioException = new IOException();
    EasyMock.expect(bufferedReaderMock.readLine()).andThrow(ioException);
    terminalErrorHandlerMock.handleError(ioException, knoxTunnelShellMock);
    EasyMock.expectLastCall();

    EasyMock.replay(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock,
        bufferedReaderMock);

    TerminalActionAuditRecorder terminalActionAuditRecorder =
        new TerminalActionAuditRecorder(terminalErrorHandlerMock, auditorMock);

    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork(resource, user, bufferedReaderMock,
            knoxTunnelShellMock);

    terminalActionAuditRecorder.auditWork(terminalAuditWork);
    EasyMock.verify(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock,
        bufferedReaderMock);
  }

  @Test
  public void testAuditWorkNullLine() throws Exception {
    String resource = "resource";
    String user = "user";

    TerminalErrorHandler terminalErrorHandlerMock =
        EasyMock.createMock(TerminalErrorHandler.class);
    Auditor auditorMock = EasyMock.createMock(Auditor.class);
    KnoxTunnelShell knoxTunnelShellMock =
        EasyMock.createMock(KnoxTunnelShell.class);
    BufferedReader bufferedReaderMock =
        EasyMock.createMock(BufferedReader.class);

    EasyMock.expect(bufferedReaderMock.readLine()).andReturn(null);
    bufferedReaderMock.close();
    EasyMock.expectLastCall();

    EasyMock.replay(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock,
        bufferedReaderMock);

    TerminalActionAuditRecorder terminalActionAuditRecorder =
        new TerminalActionAuditRecorder(terminalErrorHandlerMock, auditorMock);

    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork(resource, user, bufferedReaderMock,
            knoxTunnelShellMock);

    terminalActionAuditRecorder.auditWork(terminalAuditWork);
    EasyMock.verify(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock,
        bufferedReaderMock);
  }
}
