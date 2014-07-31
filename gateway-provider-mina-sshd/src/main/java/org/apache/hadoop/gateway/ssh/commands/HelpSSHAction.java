package org.apache.hadoop.gateway.ssh.commands;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Map;

import org.apache.sshd.common.util.NoCloseOutputStream;

public class HelpSSHAction extends AbstractAction {

  private final Map<String, AbstractAction> actions;

  public HelpSSHAction(Map<String, AbstractAction> actions) {
    super("help", "", "Print this help message.");
    this.actions = actions;
  }

  @Override
  public int handleCommand(String command, String commandLine,
                           InputStream inputStream, OutputStream outputStream, OutputStream error)
      throws IOException {
    PrintStream printStream = new PrintStream(new NoCloseOutputStream(
        outputStream));
    int longestCommand = 1;
    int longestArgs = 1;
    for (AbstractAction action : actions.values()) {
      longestCommand = Math.max(longestCommand, action.getCommand().length());
      longestArgs = Math.max(longestArgs, action.getArgGrammar().length());
    }
    printStream.print("Knox SSH Provider help.\r\n");
    String formatString = "%-" + longestCommand + "s %-" + longestArgs
        + "s %s\r\n";
    for (AbstractAction action : actions.values()) {
      printStream.format(formatString, action.getCommand(),
          action.getArgGrammar(), action.getDescription());
    }
    printStream.close();
    outputStream.flush();
    return 0;
  }
}
