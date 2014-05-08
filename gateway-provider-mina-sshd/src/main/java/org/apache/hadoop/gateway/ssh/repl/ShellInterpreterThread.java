package org.apache.hadoop.gateway.ssh.repl;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.hadoop.gateway.ssh.commands.SSHAction;
import org.apache.hadoop.gateway.ssh.commands.UnsupportedCommandAction;
import org.apache.hadoop.gateway.ssh.util.LineReaderInputStream;
import org.apache.sshd.common.util.NoCloseOutputStream;

public class ShellInterpreterThread extends Thread implements Closeable {

  private final ShellExitHandler exitHandler;
  private Map<String, SSHAction> shellActions = null;
  private final ReentrantLock stopLock = new ReentrantLock();
  private boolean stop = false;
  private final String username;
  private final String topology;
  private final InputStream inputStream;
  private final OutputStream output;
  private final OutputStream error;

  public ShellInterpreterThread(KnoxTunnelShell knoxShell, ShellExitHandler exitHandler,
                                InputStream inputStream, OutputStream output,
                                OutputStream error,
                                Map<String, SSHAction> actionMap) {
    super("ShellInterpretedThread");
    this.username = knoxShell.getUsername();
    this.topology = knoxShell.getTopologyName();
    this.exitHandler = exitHandler;
    this.inputStream = inputStream;
    this.output = output;
    this.error = error;
    this.shellActions = actionMap;
  }

  public void run() {
    boolean run = true;
    int result = 0;
    // New lines are not handled correctly with printstream
    PrintStream consolePrinter = new PrintStream(new NoCloseOutputStream(
        output));
    /**
     * The buffered reader approach to readLine was causing the channel to pause.
     */
    LineReaderInputStream lineReaderStream = new LineReaderInputStream(inputStream);
    try {
      while (run) {
        consolePrinter.printf("%s@%s > ", username,
            topology);
        consolePrinter.flush();

        String line = null;
        try {
          line = lineReaderStream.readLine(output);
        } catch (IOException e) {
          consolePrinter.close();
          exitHandler.failure(e);
          return;
        }
        if (line == null) {
          run = false;
          continue;
        }
        consolePrinter.print("\r\n");
        consolePrinter.flush();
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
          result = action
              .handleCommand(command, unconsumedLine, lineReaderStream, output,
                  error);
        } catch (IOException e) {
          exitHandler.failure(e);
        }
        stopLock.lock();
        run = !stop;
        stopLock.unlock();
      }
    } catch (Throwable t) {
      exitHandler.failure(t);
      throw new RuntimeException(t);
    } finally {
      if (consolePrinter != null) {
        consolePrinter.close();
      }
      if (lineReaderStream != null) {
        try {
          lineReaderStream.close();
        } catch (IOException e) {
          exitHandler.failure(e);
        }
      }
    }
    exitHandler.normalExit(result);
  }

  public void setShellActions(Map<String, SSHAction> shellActions) {
    this.shellActions = shellActions;
  }

  @Override
  public void close() throws IOException {
    if (stop) {
      throw new IOException("Already stopped the shell interpreter.");
    }
    stop = true;
  };

}
