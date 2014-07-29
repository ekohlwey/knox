package org.apache.hadoop.gateway.ssh.repl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.StreamFlusher;
import org.apache.hadoop.gateway.ssh.commands.ConnectSSHAction;
import org.apache.hadoop.gateway.ssh.commands.ExitSSHAction;
import org.apache.hadoop.gateway.ssh.commands.HelpSSHAction;
import org.apache.hadoop.gateway.ssh.commands.SSHAction;
import org.apache.sshd.common.PtyMode;
import org.apache.sshd.common.util.NoCloseInputStream;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.Signal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KnoxTunnelShell implements Command {

  private static final Logger LOG = LoggerFactory
      .getLogger(KnoxTunnelShell.class);

  private ExitCallback exitCallback;
  private OutputStream errorStream;
  private OutputStream outputStream;
  private InputStream inputStream;
  private final Map<String, SSHAction> actionMap = new HashMap<String, SSHAction>();
  private final ShellExitHandler exitHandler = new ShellExitHandler(this);
  private ShellInterpreterThread interpreterThread = null;
  private final String topologyName;
  private String username;
  private final Timer timer;
  private final SSHConfiguration sshConfiguration;

  public KnoxTunnelShell(String topologyName, SSHConfiguration configuration) {
    this.topologyName = topologyName;
    this.sshConfiguration = configuration;
    this.timer = new Timer("Stream Flusher");
  }

  @Override
  public void destroy() {
    try {
      timer.cancel();
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
    this.inputStream = new NoCloseInputStream(arg0);
  }

  @Override
  public void setOutputStream(OutputStream arg0) {
    this.outputStream = arg0;
  }

  @Override
  public void start(Environment environment) throws IOException {
    Map<String, String> env = environment.getEnv();
    username = env.get(Environment.ENV_USER);
    Map<PtyMode, Integer> ptys = environment.getPtyModes();
//    environment.addSignalListener(listener, Signal.WINCH);
    List<SSHAction> actions = new ArrayList<SSHAction>();
    actions.add(new ConnectSSHAction(username, sshConfiguration, this));
    actions.add(new HelpSSHAction(actionMap));
    actions.add(new ExitSSHAction());
    for (SSHAction action : actions) {
      actionMap.put(action.getCommand(), action);
    }

    interpreterThread =  new ShellInterpreterThread(
        this, exitHandler, inputStream, outputStream, errorStream, actionMap);
    interpreterThread.start();

    timer.schedule(new StreamFlusher(outputStream),
        sshConfiguration.getStreamFlusherPeriod(),
        sshConfiguration.getStreamFlusherPeriod());
    timer.schedule(new StreamFlusher(errorStream),
        sshConfiguration.getStreamFlusherPeriod(),
        sshConfiguration.getStreamFlusherPeriod());
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

  public Object getConfiguration() {
    return sshConfiguration;
  }

}
