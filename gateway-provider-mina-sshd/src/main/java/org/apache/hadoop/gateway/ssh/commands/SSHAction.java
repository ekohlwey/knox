package org.apache.hadoop.gateway.ssh.commands;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class SSHAction {

  private final String description;
  private final String command;
  private final String argGrammar;

  public String getDescription() {
    return description;
  }

  public String getCommand() {
    return command;
  }

  public String getArgGrammar() {
    return argGrammar;
  }

  public SSHAction(String command, String argGrammar, String description) {
    this.description = description;
    this.argGrammar = argGrammar;
    this.command = command;
  }

  public abstract int handleCommand(String command, String commandLine,
      InputStream inputStream, OutputStream outputStream, OutputStream error)
      throws IOException;

}
