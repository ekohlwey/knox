package org.apache.hadoop.gateway.ssh.commands;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.or;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Map;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.SSHDeploymentContributorTBase.PipingCommandFactory;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditManager;
import org.apache.hadoop.gateway.ssh.commands.connect.TerminalSizeListener;
import org.apache.hadoop.gateway.ssh.commands.connect.SSHConnector;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.apache.hadoop.test.category.IntegrationTests;
import org.apache.sshd.SshServer;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.PtyMode;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.Signal;
import org.apache.sshd.server.SignalListener;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.session.ServerSession;
import org.bouncycastle.openssl.PEMWriter;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.google.common.io.ByteStreams;

@RunWith(JUnit4.class)
public class ConnectSSHActionITest {
  
  public static class FakeEnvironment implements Environment {

    @Override
    public Map<String, String> getEnv() {
      
      return null;
    }

    @Override
    public Map<PtyMode, Integer> getPtyModes() {
      
      return null;
    }

    @Override
    public void addSignalListener(SignalListener listener, Signal... signal) {
      
    }

    @Override
    public void addSignalListener(SignalListener listener,
        EnumSet<Signal> signals) {
     
      
    }

    @Override
    public void addSignalListener(SignalListener listener) {
      
    }

    @Override
    public void removeSignalListener(SignalListener listener) {
      
    }
    
  }

  public static class FakePtyModesSetter extends TerminalSizeListener {
    public FakePtyModesSetter() {
      super(null, null, null);
    }

    @Override
    public void signal(Signal signal) {
    }
  }

  public static class FakePtySetterFactory extends TerminalSizeListener.Factory {
    public FakePtySetterFactory() {
      super(null);
    }

    @Override
    public TerminalSizeListener getModeSetter(ChannelShell channelShell) {
      return new FakePtyModesSetter();
    }
  }

  public static final int SSHD_SERVER_PORT = 60023;
  @Rule
  public TemporaryFolder tempFolder = new TemporaryFolder();

  @SuppressWarnings("unchecked")
  @Test
  public void testConnect() throws Throwable {

    String knoxuser = "knoxuser";
    String sudoToUser = "someuser";

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(1024);
    final KeyPair pair = kpg.generateKeyPair();
    File publicKeyFile = this.tempFolder.newFile();
    PEMWriter publicWriter = new PEMWriter(new FileWriter(publicKeyFile));
    publicWriter.writeObject(pair);
    publicWriter.close();
    File privateKeyFile = this.tempFolder.newFile();
    PEMWriter privateKeyWriter = new PEMWriter(new FileWriter(privateKeyFile));
    privateKeyWriter.writeObject(pair.getPrivate());
    privateKeyWriter.close();

    SshServer server = SshServer.setUpDefaultServer();
    server.setPort(SSHD_SERVER_PORT);
    server.setKeyPairProvider(new FileKeyPairProvider(
        new String[] { publicKeyFile.toString() }));
    server.setPublickeyAuthenticator(new PublickeyAuthenticator() {

      @Override
      public boolean authenticate(String username, PublicKey key,
          ServerSession session) {
        return true;
      }
    });
    server.setUserAuthFactories(Arrays
        .<NamedFactory<UserAuth>> asList(new UserAuthPublicKey.Factory()));
    final PipedInputStream inPipe = new PipedInputStream();
    PipingCommandFactory factory = new PipingCommandFactory(inPipe);
    server.setShellFactory(factory);
    server.start();
    try {
      SSHConfiguration configuration = new SSHConfiguration();
      configuration.setKnoxKeyfile(privateKeyFile.toString());
      configuration.setLoginCommand("");
      configuration.setKnoxLoginUser(knoxuser);
      configuration.setTunnelConnectTimeout(1000);

      String simulatedTerminalInput = "magic word!\nanotherline!\n";
      BufferedReader in = new BufferedReader(new StringReader(
          simulatedTerminalInput));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ByteArrayOutputStream err = new ByteArrayOutputStream();

      TerminalAuditManager fakeTerminalAuditer = EasyMock
          .createMock(TerminalAuditManager.class);
      KnoxTunnelShell originatingShell = EasyMock
          .createMock(KnoxTunnelShell.class);
      Capture<InputStream> commandCapture = new Capture<InputStream>();
      Capture<String> resourceCapture = new Capture<String>();
      fakeTerminalAuditer.auditMessage(anyObject(String.class),
          anyObject(String.class), anyObject(String.class),
          eq(originatingShell));
      expectLastCall();
      fakeTerminalAuditer.auditStream(capture(commandCapture),
          capture(resourceCapture), eq(sudoToUser), eq(originatingShell), eq("UTF-8"));
      expectLastCall();
      fakeTerminalAuditer.auditMessage(anyObject(String.class),
          anyObject(String.class), anyObject(String.class),
          eq(originatingShell));
      expectLastCall();
      replay(originatingShell, fakeTerminalAuditer);

      SSHConnector sshConnector = new SSHConnector(configuration,
          originatingShell, new FakeEnvironment(), inPipe, out, err, "client", "UTF-8");
      ConnectSSHAction connectSSHAction = new ConnectSSHAction(sudoToUser,
          sshConnector, inPipe, out, err);
      connectSSHAction.handleCommand(simulatedTerminalInput, "localhost:"
          + SSHD_SERVER_PORT);
      out.close();
      err.close();

      assertEquals("connected error\n", new String(err.toByteArray(), "UTF-8"));
      assertEquals("connected out\n", new String(out.toByteArray(), "UTF-8"));
      assertEquals(simulatedTerminalInput,
          new String(ByteStreams.toByteArray(commandCapture.getValue())));
      assertEquals("localhost:" + SSHD_SERVER_PORT, resourceCapture.getValue());

      byte[] simulatedInputSink = new byte[simulatedTerminalInput.length()];
      inPipe.read(simulatedInputSink);
      assertEquals(simulatedTerminalInput, new String(simulatedInputSink,
          "UTF-8"));
      assertEquals(-1, inPipe.read());

      verify(originatingShell, fakeTerminalAuditer);
    } finally {
      server.stop(true);
    }
  }

}
