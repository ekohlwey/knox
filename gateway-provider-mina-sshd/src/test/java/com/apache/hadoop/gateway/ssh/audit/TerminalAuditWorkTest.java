package com.apache.hadoop.gateway.ssh.audit;

import java.io.BufferedReader;
import java.io.IOException;

import org.apache.hadoop.gateway.ssh.audit.TerminalAuditWork;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class TerminalAuditWorkTest {
  
  private BufferedReader reader;
  private TerminalAuditWork work;
  private KnoxTunnelShell originatingShell;

  @Before
  public void setup(){
    reader = EasyMock.createMock(BufferedReader.class);
    originatingShell = EasyMock.createMock(KnoxTunnelShell.class);
    work = new TerminalAuditWork("resource", "user", reader, originatingShell);
  }
  
  @Test
  public void testRun() throws IOException {
    
    EasyMock.expect(reader.ready()).andReturn(true);
    EasyMock.replay(reader);
    
    work.run();
    
    EasyMock.verify(reader);
    
  }
  
  @Test
  public void testRunWithIOException() throws IOException {
    EasyMock.expect(reader.ready()).andThrow(new IOException());
    EasyMock.replay(reader);
    
    originatingShell.destroy();
    EasyMock.expectLastCall();
    EasyMock.replay(originatingShell);
    
    work.run();
    
    EasyMock.verify(reader, originatingShell);
  }

}
