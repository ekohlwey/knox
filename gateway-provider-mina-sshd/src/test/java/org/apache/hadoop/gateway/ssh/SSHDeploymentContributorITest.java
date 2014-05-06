package org.apache.hadoop.gateway.ssh;

import static junit.framework.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.hadoop.gateway.deploy.DeploymentContext;
import org.apache.hadoop.gateway.topology.Param;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.SshServer;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.UserAuthPassword;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.session.ServerSession;
import org.bouncycastle.openssl.PEMWriter;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RunWith(FrameworkRunner.class)
@CreateDS(name = "KnoxLDAPPasswordAuthenticatorITest-class", enableChangeLog = false, partitions = { @CreatePartition(name = "example", suffix = "dc=example,dc=com", contextEntry = @ContextEntry(entryLdif = "dn: dc=example,dc=com\n"
    + "objectClass: domain\n" + "dc: example")) })
@CreateLdapServer(transports = { @CreateTransport(address = "localhost", protocol = "LDAP", port = 60389) })
@ApplyLdifs({
    // client
    "dn: uid=client,dc=example,dc=com", "objectClass: top",
    "objectClass: person", "objectClass: inetOrgPerson", "cn: client",
    "sn: client", "uid: client", "ou: someOU", "userPassword: secret" })
/**
 * SSH Deployment Contributor Test
 * 
 * Setting up LDAP, KDC, SSH Provider, and client to test the "help" command
 */
public class SSHDeploymentContributorITest extends AbstractLdapTestUnit {

  public static class PipingCommandFactory implements Factory<Command> {

    private final PipedOutputStream outPipe;

    public PipingCommandFactory(PipedInputStream inPipe) {
      outPipe = new PipedOutputStream();
      try {
        outPipe.connect(inPipe);
      } catch (IOException e) {
        LOG.error("Can't close pipe", e);
      }
    }

    @Override
    public Command create() {
      return new Command() {

        private InputStream inputStream;
        private OutputStream out;
        private OutputStream err;
        private ExitCallback callback;

        @Override
        public void start(Environment env) throws IOException {
          new Thread() {
            @Override
            public void run() {
              byte[] buffer = new byte[1024];
              int read;
              try {
                while ((read = inputStream.read(buffer)) > 0) {
                  outPipe.write(buffer, 0, read);
                  outPipe.flush();
                }
              } catch (IOException e) {
                LOG.error("Cant write to pipe", e);
              } finally {
                try {
                  outPipe.close();
                } catch (IOException e) {
                  LOG.error("Cant close pipe", e);
                }
                callback.onExit(0);
              }
            }
          }.start();
          try {
            out.write("connected out\n".getBytes());
            out.flush();
          } catch (IOException e) {
            LOG.error("Unable to write out connection message.", e);
          }
          try {
            err.write("connected error\n".getBytes());
            err.flush();
          } catch (IOException e) {
            LOG.error("Unable to write error connection message.", e);
          }
        }

        @Override
        public void setOutputStream(OutputStream out) {
          this.out = out;
        }

        @Override
        public void setInputStream(final InputStream in) {
          this.inputStream = in;
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
          this.callback = callback;
        }

        @Override
        public void setErrorStream(OutputStream err) {
          this.err = err;
        }

        @Override
        public void destroy() {

        }
      };
    }
  }

  private static final Logger LOG = LoggerFactory
      .getLogger(SSHDeploymentContributorITest.class);

  @Rule
  public TemporaryFolder tempFolder = new TemporaryFolder();

  private class TestProvider extends Provider {

    private TestProvider() {
      super();

      addParam(buildParam("main.ldapRealm",
          "org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm"));
      addParam(buildParam("main.ldapGroupContextFactory",
          "org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory"));
      addParam(buildParam("main.ldapRealm.userDnTemplate",
          "uid={0},dc=example,dc=com"));
      addParam(buildParam("main.ldapRealm.authorizationEnabled", "true"));
      addParam(buildParam("main.ldapRealm.contextFactory.url",
          "ldap://localhost:60389"));
      addParam(
          buildParam("main.ldapRealm.contextFactory.authenticationMechanism",
              "simple"));
      addParam(buildParam("main.ldapRealm.contextFactory.systemUsername",
          "uid=client,dc=example,dc=com"));
      addParam(
          buildParam("main.ldapRealm.contextFactory.systemPassword", "secret"));
    }

  }

  private class TestProviderConfigurer extends ProviderConfigurer {

    private final SSHConfiguration sshConfiguration;

    public TestProviderConfigurer(SSHConfiguration sshConfiguration) {
      this.sshConfiguration = sshConfiguration;
    }

    @Override
    public SSHConfiguration configure(Provider provider) {
      return sshConfiguration;
    }
  }

  private static class TestShiroProviderConfigurer extends ProviderConfigurer {

    private final SSHConfiguration sshConfiguration;

    public TestShiroProviderConfigurer(SSHConfiguration sshConfiguration) {
      this.sshConfiguration = sshConfiguration;
    }

    @Override
    public SSHConfiguration configure(Provider provider) {
      return sshConfiguration;

    }
  }

  private static class UserAuthStaticPassword extends UserAuthPassword {

    private static class Factory extends UserAuthPassword.Factory {

      @Override
      public UserAuth create() {
        return new UserAuthStaticPassword();
      }
    }

    @Override
    public void init(ClientSession session, String service,
        List<Object> identities) throws Exception {
      super.init(session, service, Arrays.<Object> asList("secret"));
    }
  }

  private static Param buildParam(String name, String value) {
    Param param = new Param();
    param.setName(name);
    param.setValue(value);
    return param;
  }

  @Test
  public void testConnectionWithHelp() throws Throwable {

    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setPort(61022);
    configuration.setUseShiroAuth(true);
    configuration.setTunnelConnectTimeout(1000);
    configuration.setKnoxLoginUser("knox");
    String clusterName = "test";

    DeploymentContext deploymentContextMock = EasyMock.createMock(DeploymentContext.class);
    Topology topologyMock = EasyMock.createMock(Topology.class);
    EasyMock.expect(deploymentContextMock.getTopology())
        .andReturn(topologyMock);
    EasyMock.expect(topologyMock.getName()).andReturn(clusterName);
    EasyMock.replay(deploymentContextMock);

    TestProvider provider = new TestProvider();
    SSHDeploymentContributor contributor = new SSHDeploymentContributor(
        new TestProviderConfigurer(configuration));
    contributor.contributeProvider(deploymentContextMock, provider);

    SshClient client = SshClient.setUpDefaultClient();
    List<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(
        1);
    userAuthFactories.add(new UserAuthStaticPassword.Factory());
    client.setUserAuthFactories(userAuthFactories);
    client.start();
    ConnectFuture connFuture = client.connect("client", "localhost", 61022)
        .await();
    Assert.assertTrue("Could not connect to server", connFuture.isConnected());
    ClientSession session = connFuture.getSession();
    AuthFuture authfuture = session.auth().await();
    Assert.assertTrue(
        "Failed to authenticate to server: " + authfuture.getException(),
        authfuture.isSuccess());
    ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
    ByteArrayInputStream in = new ByteArrayInputStream(
        "help\n".getBytes("UTF-8"));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    channel.setOut(out);
    channel.setErr(err);
    channel.setIn(in);

    channel.open();
    channel.waitFor(ClientChannel.CLOSED, 0);
    channel.close(false);
    client.stop();
    contributor.close();

    Assert.assertTrue("Did not receive output", out.toByteArray().length > 0);
  }
  
  @Test
  public void testDeniesBadUser() throws Throwable {

    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setPort(60022);
    configuration.setUseShiroAuth(true);
    configuration.setTunnelConnectTimeout(1000);
    configuration.setKnoxLoginUser("knox");
    String clusterName = "test";

    DeploymentContext deploymentContextMock = EasyMock.createMock(DeploymentContext.class);
    Topology topologyMock = EasyMock.createMock(Topology.class);
    EasyMock.expect(deploymentContextMock.getTopology())
        .andReturn(topologyMock);
    EasyMock.expect(topologyMock.getName()).andReturn(clusterName);
    EasyMock.replay(deploymentContextMock);

    TestProvider provider = new TestProvider();
    SSHDeploymentContributor contributor = new SSHDeploymentContributor(
        new TestProviderConfigurer(configuration));
    contributor.contributeProvider(deploymentContextMock, provider);

    SshClient client = SshClient.setUpDefaultClient();
    List<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(
        1);
    userAuthFactories.add(new UserAuthStaticPassword.Factory());
    client.setUserAuthFactories(userAuthFactories);
    client.start();
    ConnectFuture connFuture = client.connect("asdfdsaf", "localhost", 60022)
        .await();
    Assert.assertTrue("Could not connect to server", connFuture.isConnected());
    ClientSession session = connFuture.getSession();
    AuthFuture authfuture = session.auth().await();
    Assert.assertFalse(
        "Authenticated to server",
        authfuture.isSuccess());
    client.stop();
  }

  @Test
  public void testConnectionWithHop() throws Throwable {
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
    server.setPort(60023);
    server.setPublickeyAuthenticator(new PublickeyAuthenticator() {

      @Override
      public boolean authenticate(String username, PublicKey key,
                                  ServerSession session) {
        return true;
      }
    });
    server.setKeyPairProvider(new FileKeyPairProvider(
        new String[] { publicKeyFile.toString() }));
    server
        .setUserAuthFactories(Arrays
            .<NamedFactory<org.apache.sshd.server.UserAuth>> asList(new UserAuthPublicKey.Factory()));
    final PipedInputStream inPipe = new PipedInputStream();
    PipingCommandFactory factory = new PipingCommandFactory(inPipe);
    server.setShellFactory(factory);
    server.start();

    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setPort(62022);
    configuration.setUseShiroAuth(true);
    configuration.setTunnelConnectTimeout(1000);
    configuration.setKnoxLoginUser("knox");
    configuration.setKnoxKeyfile(privateKeyFile.toString());
    configuration.setLoginCommand("exec sudo -iu {0} ; logout\n");
    String clusterName = "topology";

    DeploymentContext deploymentContextMock = EasyMock.createMock(DeploymentContext.class);
    Topology topologyMock = EasyMock.createMock(Topology.class);
    EasyMock.expect(deploymentContextMock.getTopology())
        .andReturn(topologyMock);
    EasyMock.expect(topologyMock.getName()).andReturn(clusterName);
    EasyMock.replay(deploymentContextMock, topologyMock);

    TestProvider provider = new TestProvider();
    SSHDeploymentContributor contributor = new SSHDeploymentContributor(
        new TestProviderConfigurer(configuration));
    contributor.contributeProvider(deploymentContextMock, provider);

    SshClient client = SshClient.setUpDefaultClient();
    List<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(
        1);
    userAuthFactories.add(new UserAuthStaticPassword.Factory());
    client.setUserAuthFactories(userAuthFactories);
    client.start();
    ConnectFuture connFuture = client.connect("client", "localhost", 62022)
        .await();
    Assert.assertTrue("Could not connect to server", connFuture.isConnected());
    ClientSession session = connFuture.getSession();
    AuthFuture authfuture = session.auth().await();
    Assert.assertTrue(
        "Failed to authenticate to server: " + authfuture.getException(),
        authfuture.isSuccess());
    ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);
    PipedInputStream in = new PipedInputStream();
    PipedOutputStream commands = new PipedOutputStream(in);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    channel.setOut(out);
    channel.setErr(err);
    channel.setIn(in);

    channel.open().await();
    commands.write(("connect localhost:" + 60023 + "\n").getBytes("UTF-8"));
    channel.waitFor(ClientChannel.CLOSED, 2000);
    //verifying that the connection is still alive
    commands.write("magic word!\n".getBytes("UTF-8"));
    channel.waitFor(ClientChannel.CLOSED, 1000);
    commands.write("another line\n".getBytes("UTF-8"));
    channel.waitFor(ClientChannel.CLOSED, 1000);
    channel.close(true);
    client.stop();
    contributor.close();
    BufferedReader reader = new BufferedReader(new InputStreamReader(inPipe));
    assertEquals("connected error\n", new String(err.toByteArray(), "UTF-8"));
    assertEquals("client@topology > connected out\n", new String(out.toByteArray(), "UTF-8"));
    assertEquals("exec sudo -iu client ; logout", reader.readLine());
    assertEquals("magic word!", reader.readLine());
    assertEquals("another line", reader.readLine());
    assertNull(reader.readLine());
    server.stop(true);
  }
}