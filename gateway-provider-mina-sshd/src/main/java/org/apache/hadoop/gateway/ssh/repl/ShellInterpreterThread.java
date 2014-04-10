package org.apache.hadoop.gateway.ssh.repl;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.hadoop.gateway.ssh.commands.SSHAction;
import org.apache.hadoop.gateway.ssh.commands.UnsupportedCommandAction;
import org.apache.sshd.common.util.NoCloseOutputStream;

public class ShellInterpreterThread extends Thread implements Closeable {

  private final ShellExitHandler exitHandler;
  private final Map<String, SSHAction> shellActions;
  private final ReentrantLock stopLock = new ReentrantLock();
  private boolean stop = false;
  private final KnoxTunnelShell knoxShell;

  public ShellInterpreterThread(KnoxTunnelShell knoxShell,
      ShellExitHandler exitHandler, Map<String, SSHAction> actionMap) {
    this.knoxShell = knoxShell;
    this.exitHandler = exitHandler;
    this.shellActions = actionMap;
  }

  public void run() {
    boolean run = true;
    int result = 0;

    // New lines are not handled correctly with printstream
    PrintStream consolePrinter = new PrintStream(new NoCloseOutputStream(knoxShell.getOutputStream()));
    BufferedReader reader = knoxShell.getReader(); // reader cannot be closed in while loop
    
    while (run) {
      consolePrinter.printf("%s@%s > ", knoxShell.getUsername(), knoxShell.getTopologyName());
      String line = null;
      try {
        line = reader.readLine();
      } catch (IOException e) {
        exitHandler.failure(e);
        return;
      }
      if (line == null) {
        run = false;
        continue;
      }
      line = line.trim();
      String command;
      String unconsumedLine;
      int spaceIndex = line.indexOf(' ');
      if (spaceIndex > 0) {
        command = line.substring(0, spaceIndex);
        // line was trimmed so we know space is not last char
        unconsumedLine = line.substring(spaceIndex + 1, line.length());
      } else {
        command = line;
        unconsumedLine = "";
      }
      SSHAction action = shellActions.get(command);
      if (action == null) {
        action = new UnsupportedCommandAction();
      }
      try {
        result = action.handleCommand(command, unconsumedLine, reader,
            knoxShell.getOutputStream(), knoxShell.getErrorStream());
      } catch (IOException e) {
        exitHandler.failure(e);
      }
      stopLock.lock();
      run = !stop;
      stopLock.unlock();
    }
    try {
      consolePrinter.close();
      reader.close();
    } catch (IOException e) {
      exitHandler.failure(e);
      return;
    }
    exitHandler.normalExit(result);
  }

  @Override
  public void close() throws IOException {
    if (stop) {
      throw new IOException("Already stopped the shell interpreter.");
    }
    stop = true;
  };

}
