package org.apache.hadoop.gateway.ssh.commands;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import org.apache.sshd.common.util.NoCloseOutputStream;

public class UnsupportedCommandAction extends AbstractAction {

  public UnsupportedCommandAction() {
    super(null, null, null);
  }

  @Override
  public int handleCommand(String command, String commandLine,
                           InputStream inputStream, OutputStream outputStream, OutputStream error)
      throws IOException {
    PrintStream errorWriter = new PrintStream(new NoCloseOutputStream(error));
    errorWriter.print("-knox: " + command + ": command not found\r\n");
    errorWriter.print("type 'help' for a list of commands\r\n");
    errorWriter.close();
    error.flush();
    return -1;
  }

}
