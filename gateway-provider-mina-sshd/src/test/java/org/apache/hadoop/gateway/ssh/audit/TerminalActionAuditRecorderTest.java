package org.apache.hadoop.gateway.ssh.audit;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import org.apache.hadoop.gateway.audit.api.Action;
import org.apache.hadoop.gateway.audit.api.ActionOutcome;
import org.apache.hadoop.gateway.audit.api.Auditor;
import org.apache.hadoop.gateway.audit.api.ResourceType;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.easymock.EasyMock;
import org.junit.Test;

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

    ByteArrayInputStream performedWorkStream =
        new ByteArrayInputStream(performedWork.getBytes("UTF-8"));
    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork(resource, user, performedWorkStream,
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
    InputStream inMock =
        EasyMock.createMock(InputStream.class);

    IOException ioException = new IOException();
    EasyMock.expect(inMock
        .read((byte[]) EasyMock.anyObject(), EasyMock.anyInt(),
            EasyMock.anyInt())).andThrow(ioException);
    terminalErrorHandlerMock.handleError(ioException, knoxTunnelShellMock);
    EasyMock.expectLastCall();
    inMock.close();
    EasyMock.expectLastCall();

    EasyMock.replay(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock,
        inMock);

    TerminalActionAuditRecorder terminalActionAuditRecorder =
        new TerminalActionAuditRecorder(terminalErrorHandlerMock, auditorMock);

    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork(resource, user, inMock,
            knoxTunnelShellMock);

    terminalActionAuditRecorder.auditWork(terminalAuditWork);
    EasyMock.verify(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock,
        inMock);
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
    InputStream inMock =
        EasyMock.createMock(InputStream.class);

    EasyMock.expect(inMock
        .read((byte[]) EasyMock.anyObject(), EasyMock.anyInt(),
            EasyMock.anyInt())).andReturn(-1);
    inMock.close();
    EasyMock.expectLastCall();

    EasyMock.replay(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock,
        inMock);

    TerminalActionAuditRecorder terminalActionAuditRecorder =
        new TerminalActionAuditRecorder(terminalErrorHandlerMock, auditorMock);

    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork(resource, user, inMock,
            knoxTunnelShellMock);

    terminalActionAuditRecorder.auditWork(terminalAuditWork);
    EasyMock.verify(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock,
        inMock);
  }


  @Test
  public void testAuditWorkMultiLine() throws Exception {
    String performedWork = "input data\r\n";
    String performedWork2 = "input data2\r\n";
    String resource = "resource";
    String user = "user";

    TerminalErrorHandler terminalErrorHandlerMock =
        EasyMock.createMock(TerminalErrorHandler.class);
    Auditor auditorMock = EasyMock.createMock(Auditor.class);
    auditorMock.audit(Action.ACCESS, user + "@" + resource + ":" + "input data",
        ResourceType.TOPOLOGY, ActionOutcome.UNAVAILABLE);
    EasyMock.expectLastCall();
    auditorMock.audit(Action.ACCESS, user + "@" + resource + ":" + "input data2",
        ResourceType.TOPOLOGY, ActionOutcome.UNAVAILABLE);
    EasyMock.expectLastCall();

    KnoxTunnelShell knoxTunnelShellMock =
        EasyMock.createMock(KnoxTunnelShell.class);

    EasyMock.replay(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock);

    TerminalActionAuditRecorder terminalActionAuditRecorder =
        new TerminalActionAuditRecorder(terminalErrorHandlerMock, auditorMock);

    PipedInputStream pipedInputStream = new PipedInputStream();
    PipedOutputStream pipedOutputStream =
        new PipedOutputStream(pipedInputStream);
    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork(resource, user, pipedInputStream,
            knoxTunnelShellMock);

    pipedOutputStream.write(performedWork.getBytes("UTF-8"));
    Thread.sleep(100);
    pipedOutputStream.write(performedWork2.getBytes("UTF-8"));
    pipedOutputStream.close();

    terminalActionAuditRecorder.auditWork(terminalAuditWork);
    EasyMock.verify(terminalErrorHandlerMock, auditorMock, knoxTunnelShellMock);
  }

}
