package org.apache.hadoop.gateway.ssh.audit;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.util.concurrent.ArrayBlockingQueue;

import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.Test;

public class TerminalAuditThreadTest {

  @SuppressWarnings("unchecked")
  @Test
  public void testRun() throws Exception {
    ArrayBlockingQueue<TerminalAuditWork> workQueueMock =
        EasyMock.createMock(ArrayBlockingQueue.class);
    TerminalActionAuditRecorder auditorMock =
        EasyMock.createMock(TerminalActionAuditRecorder.class);
    KnoxTunnelShell knoxTunnelShellMock =
        EasyMock.createMock(KnoxTunnelShell.class);

    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork("resource", "user",
            new ByteArrayInputStream("".getBytes("UTF-8")), knoxTunnelShellMock);
    EasyMock.expect(workQueueMock.take())
        .andReturn(terminalAuditWork);
    EasyMock.expect(workQueueMock.take())
        .andReturn(terminalAuditWork);
    EasyMock.expect(workQueueMock.take()).andAnswer(new IAnswer<TerminalAuditWork>() {
      @Override
      public TerminalAuditWork answer() throws Throwable {
        Thread.sleep(10000); //simulate nothing there
        return null;
      }
    });
    auditorMock.auditWork(terminalAuditWork);
    EasyMock.expectLastCall().times(2);

    EasyMock.replay(workQueueMock, auditorMock);

    TerminalAuditThread terminalAuditThread =
        new TerminalAuditThread(workQueueMock, auditorMock);
    terminalAuditThread.start();
    Thread.sleep(100);
    terminalAuditThread.close();

    EasyMock.verify(workQueueMock, auditorMock);
  }
}
