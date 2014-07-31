package org.apache.hadoop.gateway.ssh.commands;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import org.apache.sshd.common.util.NoCloseOutputStream;

public class UnsupportedCommandAction extends AbstractAction {

  public UnsupportedCommandAction(InputStream inputStream, OutputStream outputStream, OutputStream errorStream) {
    super(null, null, null, inputStream, outputStream, errorStream);
  }

  @Override
  public int handleCommand(String command, String commandLine)
      throws IOException {
    OutputStream error = getErrorStream();
    PrintStream errorWriter = new PrintStream(new NoCloseOutputStream(error));
    errorWriter.print("-knox: " + command + ": command not found\r\n");
    errorWriter.print("type 'help' for a list of commands\r\n");
    errorWriter.close();
    error.flush();
    return -1;
  }

}
