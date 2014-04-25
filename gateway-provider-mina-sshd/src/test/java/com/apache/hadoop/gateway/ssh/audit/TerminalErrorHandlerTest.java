package com.apache.hadoop.gateway.ssh.audit;

import org.apache.hadoop.gateway.ssh.audit.TerminalErrorHandler;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class TerminalErrorHandlerTest {
  
  private TerminalErrorHandler errorHandler;
  private KnoxTunnelShell originatingShell;
  
  @Before
  public void setup(){
    originatingShell = EasyMock.createMock(KnoxTunnelShell.class);
    errorHandler = new TerminalErrorHandler();
  }
  
  @Test
  public void testHandleError(){
    originatingShell.destroy();
    EasyMock.expectLastCall();
    EasyMock.replay(originatingShell);
    
    errorHandler.handleError(null, originatingShell);

    EasyMock.verify(originatingShell);
  }

}
