package com.apache.hadoop.gateway.ssh.audit;

import java.io.BufferedReader;
import java.io.IOException;

import org.apache.hadoop.gateway.audit.api.Action;
import org.apache.hadoop.gateway.audit.api.ActionOutcome;
import org.apache.hadoop.gateway.audit.api.Auditor;
import org.apache.hadoop.gateway.audit.api.ResourceType;
import org.apache.hadoop.gateway.ssh.audit.TerminalActionAuditRecoder;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditWork;
import org.apache.hadoop.gateway.ssh.audit.TerminalErrorHandler;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class TerminalActionAuditRecorderTest {
  
  private TerminalErrorHandler handler;
  private TerminalActionAuditRecoder terminalActionAuditRecorder;
  private TerminalAuditWork work;
  private BufferedReader reader;
  private Auditor AUDITOR;

  @Before
  public void setup() {
    AUDITOR = EasyMock.createMock(Auditor.class);
    work = EasyMock.createMock(TerminalAuditWork.class);
    handler = EasyMock.createMock(TerminalErrorHandler.class);
    reader = EasyMock.createMock(BufferedReader.class);
    terminalActionAuditRecorder = new TerminalActionAuditRecoder(handler);
  }
  
  @Test
  public void testAuditWork() throws Exception{
    
    EasyMock.expect(reader.readLine()).andReturn("hello world");
    EasyMock.replay(reader);
    
    EasyMock.expect(work.getReader()).andReturn(reader);
    EasyMock.expect(work.getUser()).andReturn("foo");
    EasyMock.expect(work.getResource()).andReturn("bar");
    EasyMock.replay(work);
    
    AUDITOR.audit(Action.ACCESS, "foo@bar:hello world", ResourceType.TOPOLOGY, ActionOutcome.UNAVAILABLE);
    EasyMock.expectLastCall();
    EasyMock.replay(AUDITOR);
  
    terminalActionAuditRecorder.auditWork(work);
    
    EasyMock.verify(work, reader);
  }
  
  @Test
  public void testAuditWorkNoLine() throws Exception{
    
    EasyMock.expect(reader.readLine()).andReturn(null);
    reader.close();
    EasyMock.expectLastCall();
    EasyMock.replay(reader);
    
    EasyMock.expect(work.getReader()).andReturn(reader);
    EasyMock.expect(work.getUser()).andReturn("foo");
    EasyMock.expect(work.getResource()).andReturn("bar");
    EasyMock.replay(work);
  
    terminalActionAuditRecorder.auditWork(work);
    
    EasyMock.verify(work, reader);
  }
  
  @Test
  public void testThrowsIoException() throws Exception{
    
    EasyMock.expect(reader.readLine()).andThrow(new IOException());
    EasyMock.replay(reader);
    
    EasyMock.expect(work.getReader()).andReturn(reader);
    EasyMock.expect(work.getOriginatingShell()).andReturn(new KnoxTunnelShell("foo"));
    EasyMock.replay(work);
  
    terminalActionAuditRecorder.auditWork(work);
    
    EasyMock.verify(work, reader);
  }  
  

}
