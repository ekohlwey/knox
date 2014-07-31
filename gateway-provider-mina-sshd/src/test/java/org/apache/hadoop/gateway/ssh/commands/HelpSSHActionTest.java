package org.apache.hadoop.gateway.ssh.commands;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;

import org.junit.Test;

public class HelpSSHActionTest {

  @Test
  public void testHelpOutput() throws Exception {

    TestSSHAction action1 =
        new TestSSHAction("action1", "", "Action1 Description");
    TestSSHAction action2 =
        new TestSSHAction("action2", "", "Action2 Description");
    TestSSHAction actionWArgs = new TestSSHAction("connect", "<host>[:<port>]",
        "Connect to a server within the Knox cluster.");
    HashMap<String, AbstractAction> actionHashMap = new HashMap<String, AbstractAction>();
    actionHashMap.put("action1", action1);
    actionHashMap.put("action2", action2);
    actionHashMap.put("connect", actionWArgs);

    HelpSSHAction helpSSHAction = new HelpSSHAction(actionHashMap);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    helpSSHAction
        .handleCommand("help", "", new ByteArrayInputStream("".getBytes()), out,
            err);

    assertEquals("Knox SSH Provider help.\r\n" +
        "connect <host>[:<port>] Connect to a server within the Knox cluster.\r\n" +
        "action2                 Action2 Description\r\n" +
        "action1                 Action1 Description\r\n",
        new String(out.toByteArray(), "UTF-8"));
    assertEquals("", new String(err.toByteArray(), "UTF-8"));
  }

  private static class TestSSHAction extends AbstractAction {

    public TestSSHAction(String command, String argGrammar,
                         String description) {
      super(command, argGrammar, description);
    }

    @Override
    public int handleCommand(String command, String commandLine,
                             InputStream inputStream, OutputStream outputStream,
                             OutputStream error) throws IOException {
      return 0;
    }
  }

}