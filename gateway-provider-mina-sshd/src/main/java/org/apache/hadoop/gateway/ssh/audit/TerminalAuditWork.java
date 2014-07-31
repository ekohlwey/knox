package org.apache.hadoop.gateway.ssh.audit;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.BlockingQueue;

import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TerminalAuditWork {

  private static final Logger LOG = LoggerFactory
      .getLogger(TerminalAuditWork.class);

  private final InputStream inputStream;
  private final String user;
  private final KnoxTunnelShell originatingShell;
  private final String resource;
  private final String encoding;

  public TerminalAuditWork(String resource, String user, InputStream inputStream,
      KnoxTunnelShell originatingShell, String encoding) {
    this.inputStream = inputStream;
    this.user = user;
    this.resource = resource;
    this.originatingShell = originatingShell;
    this.encoding = encoding;
  }

  public KnoxTunnelShell getOriginatingShell() {
    return originatingShell;
  }

  public InputStream getStream() {
    return inputStream;
  }

  public String getResource() {
    return resource;
  }

  public String getUser() {
    return user;
  }

  public String getEncoding() {
    return encoding;
  }

}