package org.apache.hadoop.gateway.ssh.audit;

import java.io.IOException;

import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TerminalErrorHandler {

  Logger LOG = LoggerFactory.getLogger(TerminalErrorHandler.class);

  public void handleError(IOException e, KnoxTunnelShell originatingShell) {
    LOG.error("Unable to read piped audit log stream. "
        + "Audits may have been lost. Killing the original shell.", e);
    originatingShell.destroy();
  }

}