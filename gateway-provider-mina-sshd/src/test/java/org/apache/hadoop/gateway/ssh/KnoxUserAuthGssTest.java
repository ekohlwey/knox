package org.apache.hadoop.gateway.ssh;

import org.apache.hadoop.gateway.audit.api.Auditor;
import org.apache.hadoop.gateway.ssh.KnoxUserAuthGSS.Factory;
import org.apache.sshd.common.util.Buffer;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.session.ServerSession;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class KnoxUserAuthGssTest {
  
  private ServerSession session;
  private String username;
  private String service;
  private Buffer buffer;
  
  private UserAuth userAuth;
  private Auditor AUDITOR;

  @Before  
  public void setUp() {  
      session = EasyMock.createMock(ServerSession.class);  
      AUDITOR = EasyMock.createMock(Auditor.class);  
      
      Factory factory = new KnoxUserAuthGSS.Factory();
      userAuth = factory.create();
  }  

  @Test
  public void testUserAuthAudit() throws Throwable{
    
  }
  
}
