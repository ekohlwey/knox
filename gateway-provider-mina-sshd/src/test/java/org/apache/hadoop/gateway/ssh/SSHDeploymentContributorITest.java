package org.apache.hadoop.gateway.ssh;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.kerberos.client.KdcConfig;
import org.apache.directory.kerberos.client.KdcConnection;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.kerberos.kdc.KerberosTestUtils;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.UserAuthPassword;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.NamedFactory;
import org.junit.Assert;
import org.junit.Before;
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

  private class TestProvider extends Provider {
    @Override
    public Topology getTopology() {
      Topology topology = new Topology();
      topology.setName("topology");
      return topology;
    }
  }

  private class TestProviderConfigurer extends ProviderConfigurer {

    @Override
    public SSHConfiguration configure(Provider provider) {
      return new SSHConfiguration(60022, null, false, null, null, 0,
          "dc=example,dc=com", "uid=client,dc=example,dc=com", "secret", null,
          "ldap://localhost:60389", "cn", null, "uid={0},dc=example,dc=com",
          null, true);

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
      super.init(session, service, Arrays.<Object>asList("secret"));
    }
  }

  @Test
  public void testConnection() throws Throwable {
    
    SSHDeploymentContributor contributor = new SSHDeploymentContributor(new TestProviderConfigurer());
    
    contributor.contributeProvider(null, new TestProvider());
    SshClient client = SshClient.setUpDefaultClient();
    List<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(
        1);
    userAuthFactories.add(new UserAuthStaticPassword.Factory());
    client.setUserAuthFactories(userAuthFactories);
    client.start();
    ConnectFuture connFuture = client.connect("client", "localhost",
        60022).await();
    Assert.assertTrue("Could not connect to server",
        connFuture.isConnected());
    ClientSession session = connFuture.getSession();
    AuthFuture authfuture = session.auth().await();
    Assert.assertTrue(
        "Failed to authenticate to server: " + authfuture.getException(),
        authfuture.isSuccess());
    ClientChannel channel = session
        .createChannel(ClientChannel.CHANNEL_SHELL);
    ByteArrayInputStream in = new ByteArrayInputStream("help\n".getBytes("UTF-8"));
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    channel.setOut(out);
    channel.setErr(err);
    channel.setIn(in);;
    channel.open();
    channel.waitFor(ClientChannel.CLOSED, 0); 
    channel.close(false);
    client.stop();
    contributor.close();

    Assert.assertTrue("Did not receive output",
        out.toByteArray().length > 0);
  }

}