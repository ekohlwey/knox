package org.apache.hadoop.gateway.ssh.repl;

import org.apache.sshd.server.Environment;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;

public class KnoxTunnelShellTest {
  
  private KnoxTunnelShell shell;
  private ShellInterpreterThread interpreterThread;
  private Environment env;

  @Before
  public void setup(){
    interpreterThread = EasyMock.createMock(ShellInterpreterThread.class);
    env = EasyMock.createMock(Environment.class);
    shell = new KnoxTunnelShell("test");
  }
  
  @Test //TODO
  public void testDestroy(){
    
  }
  
  @Test //TODO
  public void testStart(){
    
  }

}
