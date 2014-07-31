package org.apache.hadoop.gateway.ssh.commands.connect;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

import org.apache.sshd.common.util.NoCloseOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ErrorMessagePrinter {

  public static class Factory {
    public ErrorMessagePrinter getPrinter(OutputStream errorOut) {
      return new ErrorMessagePrinter(errorOut);
    }
  }

  private static final Logger LOG = LoggerFactory
      .getLogger(ErrorMessagePrinter.class);

  private final OutputStream error;

  public ErrorMessagePrinter(OutputStream error) {
    this.error = error;
  }

  void printErrorMessage(String errMessage) {
    PrintWriter errorOut = new PrintWriter(new NoCloseOutputStream(error));
    errorOut.println(errMessage);
    errorOut.close();
    try {
      error.flush();
    } catch (IOException e) {
      LOG.error("Exception occurred flushing Error Outputstream");
    }
  }

}
