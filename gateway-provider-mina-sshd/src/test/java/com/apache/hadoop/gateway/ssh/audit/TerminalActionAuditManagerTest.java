package com.apache.hadoop.gateway.ssh.audit;

import java.util.concurrent.ArrayBlockingQueue;

import org.apache.hadoop.gateway.ssh.audit.TerminalAuditManager;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditWork;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class TerminalActionAuditManagerTest {

  private TerminalAuditManager manager;
  ArrayBlockingQueue<TerminalAuditWork> terminalWorkQueue;

  @Before
  public void setup(){
    terminalWorkQueue = EasyMock.createMock(ArrayBlockingQueue.class);
    manager = TerminalAuditManager.get();
  }
  
  @Test
  public void testAuditStream() {
    
    EasyMock.expect(terminalWorkQueue.add(EasyMock.anyObject(TerminalAuditWork.class)));
    EasyMock.replay(terminalWorkQueue);
    
    manager.auditStream(null, "resouce", "user", null);
    
    EasyMock.verify(terminalWorkQueue);
  }
}
