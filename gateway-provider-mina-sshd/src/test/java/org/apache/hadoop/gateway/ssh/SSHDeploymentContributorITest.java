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
import org.apache.hadoop.gateway.ssh.SSHDeploymentContributorTBase.PipingCommandFactory;
import org.apache.hadoop.gateway.ssh.SSHDeploymentContributorTBase.TestProvider;
import org.apache.hadoop.gateway.ssh.SSHDeploymentContributorTBase.TestProviderConfigurer;
import org.apache.hadoop.gateway.ssh.SSHDeploymentContributorTBase.UserAuthStaticPassword;
import org.apache.hadoop.gateway.topology.Param;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.hadoop.test.category.IntegrationTests;
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
import org.junit.experimental.categories.Category;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.io.ByteStreams;

@RunWith(FrameworkRunner.class)
@CreateDS(name = "KnoxLDAPPasswordAuthenticatorITest-class", enableChangeLog = false, partitions = { @CreatePartition(name = "example", suffix = "dc=example,dc=com", contextEntry = @ContextEntry(entryLdif = "dn: dc=example,dc=com\n"
    + "objectClass: domain\n" + "dc: example")) })
@CreateLdapServer(transports = { @CreateTransport(address = "localhost", protocol = "LDAP", port = 60389) })
@ApplyLdifs({
    // client
    "dn: uid=client,dc=example,dc=com", "objectClass: top",
    "objectClass: person", "objectClass: inetOrgPerson", "cn: client",
    "sn: client", "uid: client", "ou: someOU", "userPassword: secret" })
public class SSHDeploymentContributorITest extends SSHDeploymentContributorTBase {

 

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
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    channel.setOut(out);
    channel.setErr(err);

    channel.open().await();
    OutputStream invertedIn = channel.getInvertedIn();

    invertedIn.write(("connect localhost:" + 60023 + "\n").getBytes("UTF-8"));
    invertedIn.flush();
    channel.waitFor(ClientChannel.CLOSED, 2000);
    //verifying that the connection is still alive
    invertedIn.write("magic word!\n".getBytes("UTF-8"));
    invertedIn.flush();
    channel.waitFor(ClientChannel.CLOSED, 100);
    invertedIn.write("another line\n".getBytes("UTF-8"));
    invertedIn.flush();
    channel.waitFor(ClientChannel.CLOSED, 1000);

    BufferedReader reader = new BufferedReader(new InputStreamReader(inPipe));
    assertEquals("connected error\n", new String(err.toByteArray(), "UTF-8"));
    assertEquals("client@topology > connect localhost:60023\n\r\nconnected out\n", new String(out.toByteArray(), "UTF-8"));
    assertEquals("exec sudo -iu client ; logout", reader.readLine());
    assertEquals("magic word!", reader.readLine());
    assertEquals("another line", reader.readLine());

    channel.close(true);
    client.stop();
    assertNull(reader.readLine());

    contributor.close();
    server.stop(true);
  }
}