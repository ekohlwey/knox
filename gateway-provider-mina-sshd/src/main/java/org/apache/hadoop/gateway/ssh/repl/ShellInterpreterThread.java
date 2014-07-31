package org.apache.hadoop.gateway.ssh.repl;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.hadoop.gateway.ssh.commands.AbstractAction;
import org.apache.hadoop.gateway.ssh.commands.UnsupportedCommandAction;
import org.apache.hadoop.gateway.ssh.util.LineReaderInputStream;
import org.apache.sshd.common.util.NoCloseOutputStream;

public class ShellInterpreterThread extends Thread implements Closeable {

  public static class ShellInterpreterErrorExitException extends Exception {
    public ShellInterpreterErrorExitException() {
    }

    public ShellInterpreterErrorExitException(Throwable cause) {
      super(cause);
    }
  }

  private final ShellExitHandler exitHandler;
  private Map<String, AbstractAction> shellActions = null;
  private final ReentrantLock stopLock = new ReentrantLock();
  private boolean stop = false;
  private final String username;
  private final String topology;
  private final InputStream inputStream;
  private final OutputStream output;
  private final OutputStream error;
  private final UnsupportedCommandAction unsupportedAction;
  private final String textEncoding;

  public ShellInterpreterThread(KnoxTunnelShell knoxShell, ShellExitHandler exitHandler,
                                InputStream inputStream, OutputStream output,
                                OutputStream error,
                                Map<String, AbstractAction> actionMap, UnsupportedCommandAction unsupportedAction, String textEncoding) {
    super("ShellInterpretedThread");
    this.username = knoxShell.getUsername();
    this.topology = knoxShell.getTopologyName();
    this.exitHandler = exitHandler;
    this.inputStream = inputStream;
    this.output = output;
    this.error = error;
    this.shellActions = actionMap;
    this.unsupportedAction = unsupportedAction;
    this.textEncoding = textEncoding;
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
    LineReaderInputStream lineReaderStream = new LineReaderInputStream(inputStream, output, textEncoding);
    try {
      while (run) {
        consolePrinter.printf("%s@%s > ", username,
            topology);
        consolePrinter.flush();

        String line = lineReaderStream.readLine();
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
        AbstractAction action = shellActions.get(command);
        if (action == null) {
          action = unsupportedAction;
        }
        try {
          result = action
              .handleCommand(command, unconsumedLine);
          //exit codes to exit the shell
          if(result == ShellExitHandler.NORMAL_EXIT) {
            run = false;
            continue;
          } else if(result == ShellExitHandler.ERROR_EXIT) {
            throw new ShellInterpreterErrorExitException();
          }

        } catch (IOException e) {
          exitHandler.failure(e);
        }
        stopLock.lock();
        run = !stop;
        stopLock.unlock();
      }
      //XXX it looks like if you ctrl-d here
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

  public void setShellActions(Map<String, AbstractAction> shellActions) {
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
