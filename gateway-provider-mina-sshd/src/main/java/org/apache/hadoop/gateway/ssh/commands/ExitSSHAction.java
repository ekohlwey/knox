package org.apache.hadoop.gateway.ssh.commands;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.apache.hadoop.gateway.ssh.repl.ShellExitHandler;

public class ExitSSHAction extends AbstractAction {


  public ExitSSHAction(InputStream inputStream, OutputStream outputStream, OutputStream errorStream) {
    super("exit", "", "Exit console, or Ctrl-D to exit", inputStream, outputStream, errorStream);
  }

  @Override
  public int handleCommand(String command, String commandLine)
      throws IOException {
    return ShellExitHandler.NORMAL_EXIT;
  }
}
