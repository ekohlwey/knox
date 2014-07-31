package org.apache.hadoop.gateway.ssh.commands;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Map;

import org.apache.hadoop.gateway.ssh.repl.ShellExitHandler;
import org.apache.sshd.common.util.NoCloseOutputStream;

public class ExitSSHAction extends AbstractAction {


  public ExitSSHAction() {
    super("exit", "", "Exit console, or Ctrl-D to exit");
  }

  @Override
  public int handleCommand(String command, String commandLine,
                           InputStream inputStream, OutputStream outputStream, OutputStream error)
      throws IOException {
    return ShellExitHandler.NORMAL_EXIT;
  }
}
