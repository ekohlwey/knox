package org.apache.hadoop.gateway.ssh.repl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.input.ReaderInputStream;
import org.apache.hadoop.gateway.ssh.commands.ConnectSSHAction;
import org.apache.hadoop.gateway.ssh.commands.HelpSSHAction;
import org.apache.hadoop.gateway.ssh.commands.SSHAction;
import org.apache.sshd.common.util.NoCloseInputStream;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KnoxTunnelShell implements Command {

  private static final Logger LOG = LoggerFactory
      .getLogger(KnoxTunnelShell.class);

  private ExitCallback exitCallback;
  private OutputStream errorStream;
  private OutputStream outputStream;
  private final Map<String, SSHAction> actionMap = new HashMap<String, SSHAction>();
  private final ShellExitHandler exitHandler = new ShellExitHandler(this);
  private final ShellInterpreterThread interpreterThread = new ShellInterpreterThread(
      this, exitHandler, actionMap);
  private final String topologyName;
  private BufferedReader reader;
  private  String username;

  public KnoxTunnelShell(String topologyName) {
    this.topologyName = topologyName;
  }

  @Override
  public void destroy() {
    try {
      interpreterThread.close();
    } catch (IOException e) {
      LOG.error("Error while closing interpreter thread.", e);
    }
  }

  @Override
  public void setErrorStream(OutputStream arg0) {
    this.errorStream = arg0;
  }

  @Override
  public void setExitCallback(ExitCallback arg0) {
    this.exitCallback = arg0;
  }

  @Override
  public void setInputStream(InputStream arg0) {
    this.reader = new BufferedReader(new InputStreamReader(
        new NoCloseInputStream(arg0)));
  }

  @Override
  public void setOutputStream(OutputStream arg0) {
    this.outputStream = arg0;
  }

  @Override
  public void start(Environment arg0) throws IOException {
    Map<String, String> env = arg0.getEnv();
    username = env.get(Environment.ENV_USER);
    List<SSHAction> actions = new ArrayList<SSHAction>();
    actions.add(new ConnectSSHAction(username, null));
    actions.add(new HelpSSHAction(actionMap));
    for (SSHAction action : actions) {
      actionMap.put(action.getCommand(), action);
    }
    interpreterThread.start();
  }

  public String getTopologyName() {
    return topologyName;
  }

  public ExitCallback getExitCallback() {
    return exitCallback;
  }

  public OutputStream getErrorStream() {
    return errorStream;
  }

  public OutputStream getOutputStream() {
    return outputStream;
  }
  
  public String getUsername() {
    return username;
  }

  /**
   * Get the input stream, as a buffered reader. Since the lines typed into the
   * console are audited, we use a reader for IO. If an input stream is
   * required, wrap this buffer in a {@link ReaderInputStream}.
   */
  public BufferedReader getReader() {
    return reader;
  }

}
