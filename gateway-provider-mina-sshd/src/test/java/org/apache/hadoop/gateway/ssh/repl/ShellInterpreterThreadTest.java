package org.apache.hadoop.gateway.ssh.repl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.hadoop.gateway.ssh.commands.AbstractAction;
import org.easymock.EasyMock;
import org.junit.Test;

public class ShellInterpreterThreadTest {

  private static class TestAbstractAction extends AbstractAction {

    private final String output;
    private final String error;

    public TestAbstractAction(String command, String argGrammar,
        String description, String output, String error, InputStream input,
        OutputStream outputStream, OutputStream errorStream) {
      super(command, argGrammar, description, input, outputStream, errorStream);
      this.output = output;
      this.error = error;
    }

    @Override
    public int handleCommand(String command, String commandLine)
        throws IOException {
      if (output != null) {
        getOutputStream().write(output.getBytes("UTF-8"));
        getOutputStream().write("\r\n".getBytes("UTF-8"));
        getOutputStream().flush();
      }
      if (error != null) {
        getErrorStream().write(error.getBytes("UTF-8"));
        getErrorStream().write("\r\n".getBytes("UTF-8"));
        getErrorStream().flush();
      }
      return 0;
    }
  }

  @Test
  public void testShell() throws Exception {
    PipedInputStream cmdStream = new PipedInputStream();
    PipedOutputStream writeCmdStream = new PipedOutputStream(cmdStream);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    
    // verifying the output of the console
    Map<String, AbstractAction> actionMap = new HashMap<String, AbstractAction>();
    actionMap.put("action1", new TestAbstractAction("action1", "", "",
        "Output Action1", "Error Action1", cmdStream, out, err));
    actionMap.put("action2", new TestAbstractAction("action2", "", "",
        "Output Action2", "Error Action2", cmdStream, out, err));

    KnoxTunnelShell knoxTunnelShell = EasyMock
        .createMock(KnoxTunnelShell.class);
    ShellExitHandler shellExitHandler = EasyMock
        .createMock(ShellExitHandler.class);

    EasyMock.expect(knoxTunnelShell.getUsername()).andReturn("user");
    EasyMock.expect(knoxTunnelShell.getTopologyName()).andReturn("topo");

    EasyMock.replay(knoxTunnelShell);

    
    ShellInterpreterThread shellInterpreterThread = null;
    try {
      shellInterpreterThread = new ShellInterpreterThread(knoxTunnelShell,
          shellExitHandler, cmdStream, out, err, actionMap, null, null);
      shellInterpreterThread.start();

      // write action1
      writeCmdStream.write("action1\n".getBytes("UTF-8"));
      Thread.sleep(100);
      assertEquals("user@topo > action1\n\r\nOutput Action1\r\nuser@topo > ",
          new String(out.toByteArray(), "UTF-8"));
      assertEquals("Error Action1\r\n", new String(err.toByteArray(), "UTF-8"));
    } finally {
      writeCmdStream.close();
      if (shellInterpreterThread != null)
        shellInterpreterThread.close();
      out.close();
      err.close();
    }

    EasyMock.verify(knoxTunnelShell);
  }

  @Test
  public void testCtrlD() throws Exception {
    // verifying the output of the console
    Map<String, AbstractAction> actionMap = new HashMap<String, AbstractAction>();

    KnoxTunnelShell knoxTunnelShell = EasyMock
        .createMock(KnoxTunnelShell.class);
    ShellExitHandler shellExitHandler = EasyMock
        .createMock(ShellExitHandler.class);

    EasyMock.expect(knoxTunnelShell.getUsername()).andReturn("user");
    EasyMock.expect(knoxTunnelShell.getTopologyName()).andReturn("topo");

    EasyMock.replay(knoxTunnelShell);

    PipedInputStream cmdStream = new PipedInputStream();
    PipedOutputStream writeCmdStream = new PipedOutputStream(cmdStream);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    ShellInterpreterThread shellInterpreterThread = null;
    try {
      shellInterpreterThread = new ShellInterpreterThread(knoxTunnelShell,
          shellExitHandler, cmdStream, out, err, actionMap, null, null);
      shellInterpreterThread.start();

      // write action1
      writeCmdStream.write("action1\u0004\n".getBytes("UTF-8"));
      Thread.sleep(100);
      assertEquals("user@topo > action1",
          new String(out.toByteArray(), "UTF-8"));

      try {
        writeCmdStream.write("action2\n".getBytes("UTF-8")); // shell should be
                                                             // closed
        fail();
      } catch (IOException ioe) {
        // Pipe is closed
      }
    } finally {
      writeCmdStream.close();
      if (shellInterpreterThread != null)
        shellInterpreterThread.close();
      out.close();
      err.close();
    }

    EasyMock.verify(knoxTunnelShell);
  }

}