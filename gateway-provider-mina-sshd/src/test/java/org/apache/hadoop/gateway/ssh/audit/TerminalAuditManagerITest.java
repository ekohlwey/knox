package org.apache.hadoop.gateway.ssh.audit;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.util.List;

import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;

import com.google.common.io.CharStreams;
import junit.framework.TestCase;

public class TerminalAuditManagerITest {

  @Test
  public void testAudit() throws Exception {
    KnoxTunnelShell knoxTunnelShell = EasyMock.createMock(KnoxTunnelShell.class);
    TerminalActionAuditRecorder terminalActionAuditRecorderMock =
        EasyMock.createMock(TerminalActionAuditRecorder.class);


    Capture<TerminalAuditWork> terminalAuditWorkCapture = new Capture<TerminalAuditWork>();
    terminalActionAuditRecorderMock.auditWork(
        EasyMock.capture(terminalAuditWorkCapture));
    EasyMock.expectLastCall().times(2);
    EasyMock.replay(terminalActionAuditRecorderMock);

    int queueSize = 2;
    TerminalAuditManager manager =
        new TerminalAuditManager(terminalActionAuditRecorderMock, queueSize);

    String resource = "resource";
    String user = "user";
    String data = "input data";
    TerminalAuditWork terminalAuditWork =
        new TerminalAuditWork(resource, user,
            new BufferedReader(new StringReader(data)),
            knoxTunnelShell);
    manager
        .auditStream(new ByteArrayInputStream(data.getBytes()), resource, user,
            knoxTunnelShell);
    manager
        .auditStream(new ByteArrayInputStream(data.getBytes()), resource, user,
            knoxTunnelShell);
    Thread.sleep(100); //wait for audits to be picked up

    EasyMock.verify(terminalActionAuditRecorderMock);
    assertTrue(terminalAuditWorkCapture.hasCaptured());
    TerminalAuditWork value = terminalAuditWorkCapture.getValue();
    assertEquals(resource, value.getResource());
    assertEquals(user, value.getUser());
    assertEquals(knoxTunnelShell, value.getOriginatingShell());
    assertEquals(data, CharStreams.toString(value.getReader()));
  }
}
