package org.apache.hadoop.gateway.ssh.commands;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Arrays;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.SSHDeploymentContributorITest.PipingCommandFactory;
import org.apache.hadoop.gateway.ssh.audit.TerminalAuditManager;
import org.apache.hadoop.gateway.ssh.commands.ConnectSSHAction.SSHConnector;
import org.apache.hadoop.gateway.ssh.repl.KnoxTunnelShell;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.session.ServerSession;
import org.bouncycastle.openssl.PEMWriter;
import org.easymock.EasyMock;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ConnectSSHActionITest {

  public static final int SSHD_SERVER_PORT = 60023;
  @Rule
  public TemporaryFolder tempFolder = new TemporaryFolder();

  @SuppressWarnings("unchecked")
  @Test
  public void testConnect() throws Throwable {

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
      configuration.setTunnelConnectTimeout(1000);

      String simulatedTerminalInput = "magic word!\nanotherline!\n";
      ByteArrayInputStream in = new ByteArrayInputStream(
          (simulatedTerminalInput).getBytes("UTF-8"));
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ByteArrayOutputStream err = new ByteArrayOutputStream();

      TerminalAuditManager fakeTerminalAuditer = EasyMock
          .createMock(TerminalAuditManager.class);
      KnoxTunnelShell originatingShell = EasyMock
          .createMock(KnoxTunnelShell.class);
      fakeTerminalAuditer.auditStream(anyObject(InputStream.class),
          anyObject(String.class), eq("someuser"), eq(originatingShell));
      expectLastCall();
      replay(originatingShell, fakeTerminalAuditer);
      SSHConnector connector = new SSHConnector("knoxuser", configuration,
          fakeTerminalAuditer, originatingShell);
      connector.connectSSH("someuser", "localhost", SSHD_SERVER_PORT, new BufferedReader(
          new InputStreamReader(in)), out, err);
      out.close();
      err.close();

      assertEquals("connected error\n", new String(err.toByteArray(), "UTF-8"));
      assertEquals("connected out\n", new String(out.toByteArray(), "UTF-8"));

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
