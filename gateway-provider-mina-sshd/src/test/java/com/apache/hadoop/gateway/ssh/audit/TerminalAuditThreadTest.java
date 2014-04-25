package com.apache.hadoop.gateway.ssh.audit;

import java.io.IOException;
import java.util.concurrent.ArrayBlockingQueue;

import org.apache.hadoop.gateway.ssh.audit.TerminalActionAuditRecoder;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditThread;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditWork;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class TerminalAuditThreadTest {
  
  private TerminalAuditThread auditThead;
  private ArrayBlockingQueue<TerminalAuditWork> workQueue;
  private TerminalActionAuditRecoder auditor;
  private TerminalAuditWork work;

  @Before
  public void setup(){
    auditor = EasyMock.createMock(TerminalActionAuditRecoder.class);
    work = new TerminalAuditWork("resource", "user", null, null);
    
    workQueue = new ArrayBlockingQueue<TerminalAuditWork>(1);
    workQueue.add(work);
    
    auditThead = new TerminalAuditThread(workQueue, auditor);
  }
  
  @Test
  public void testRun() {
    
    auditor.auditWork(work);
    EasyMock.expectLastCall().anyTimes();
    EasyMock.replay(auditor);
    
    auditThead.start();
    
    auditThead.close();
    
    EasyMock.verify(auditor);
  }

}
