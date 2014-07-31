package org.apache.hadoop.gateway.ssh.commands;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class AbstractAction {

  private final String description;
  private final String command;
  private final String argGrammar;
  private final InputStream inputStream;
  private final OutputStream outputStream;
  private final OutputStream errorStream;

  public String getDescription() {
    return description;
  }

  public String getCommand() {
    return command;
  }

  public String getArgGrammar() {
    return argGrammar;
  }

  public AbstractAction(String command, String argGrammar, String description, InputStream inputStream, OutputStream outputStream, OutputStream errorStream) {
    this.description = description;
    this.argGrammar = argGrammar;
    this.command = command;
    this.inputStream= inputStream;
    this.outputStream = outputStream;
    this.errorStream = errorStream;
  }

  public abstract int handleCommand(String command, String commandLine)
      throws IOException;
  
  protected OutputStream getErrorStream() {
    return errorStream;
  }
  
  protected InputStream getInputStream() {
    return inputStream;
  }
  
  protected OutputStream getOutputStream() {
    return outputStream;
  }

}
