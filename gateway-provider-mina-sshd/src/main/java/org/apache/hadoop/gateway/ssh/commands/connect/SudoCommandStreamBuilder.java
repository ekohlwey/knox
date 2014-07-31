package org.apache.hadoop.gateway.ssh.commands.connect;

import static java.nio.charset.Charset.forName;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.SequenceInputStream;

import org.apache.commons.io.input.TeeInputStream;
import org.apache.hadoop.gateway.ssh.SSHConfiguration;

public class SudoCommandStreamBuilder {

  private final SSHConfiguration sshConfiguration;

  public SudoCommandStreamBuilder(SSHConfiguration sshConfiguration) {
    this.sshConfiguration = sshConfiguration;
  }

  public InputStream buildSudoCommand(String sudoToUser, InputStream command,
      PipedInputStream loggingInputStream) throws IOException {
    PipedOutputStream loggingOutputStream = new PipedOutputStream(
        loggingInputStream);
    InputStream tee = new TeeInputStream(command, loggingOutputStream, true);

    String sudoCommand = sshConfiguration.getLoginCommand();
    String sudoCommandWithUser = sudoCommand.replace("{0}", sudoToUser);
    return new SequenceInputStream(new ByteArrayInputStream(
        sudoCommandWithUser.getBytes(forName("UTF-8"))), tee);
  }
}