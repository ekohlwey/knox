package org.apache.hadoop.gateway.ssh;

import java.io.File;
import java.io.IOException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.kerberos.kdc.AbstractKnoxKerberosITest;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.KerberosUtils;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;
import org.apache.directory.shared.kerberos.crypto.checksum.ChecksumType;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.util.NoCloseOutputStream;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateDS(name = "KerberosUdpIT-class",
  partitions = {
    @CreatePartition(name = "example", suffix = "dc=example,dc=com")},
    additionalInterceptors = { KeyDerivationInterceptor.class })
@CreateLdapServer(transports = { @CreateTransport(protocol = "LDAP") })
@CreateKdcServer(transports = { @CreateTransport(protocol = "TCP", port = 6086) })
@ApplyLdifFiles("org/apache/directory/server/kerberos/kdc/KerberosIT.ldif")
public class SSHDeploymentContributorTest extends AbstractKnoxKerberosITest {
  
  public static final String PRINCIPLE = LDAP_SERVICE_NAME + "/" + USER_UID + "@" + REALM;
  public static final String COMMAND = "help";
  public static final Integer PORT = 6087;

  @Rule
  public TemporaryFolder testFolder = new TemporaryFolder();
  
  private class TestProvider extends Provider {
    
    @Override
    public Topology getTopology() {
      Topology topology = new Topology();
      topology.setName("Test Topology");
      return topology;
    }

    public File generateKeytab() {
      
      Keytab keytab = Keytab.getInstance();
      File keytabFile = null;
      
      try { 
        keytabFile = testFolder.newFile();
        long principalType = 1;
        Date date = null;
  
        synchronized (KerberosUtils.UTC_DATE_FORMAT) {
          try {
            date = KerberosUtils.UTC_DATE_FORMAT.parse("20070217235745Z");
          } catch (ParseException e) {
            e.printStackTrace();
          }
        }
  
        KerberosTime timeStamp = new KerberosTime(date.getTime());
  
        Map<EncryptionType, EncryptionKey> keys = KerberosKeyFactory
            .getKerberosKeys(PRINCIPLE, USER_PASSWORD);
  
        KeytabEntry keytabEntry = new KeytabEntry(
            PRINCIPLE, 
            principalType,
            timeStamp, 
            (byte) 1, 
            keys.get(EncryptionType.DES_CBC_MD5));
        
        List<KeytabEntry> entry = Arrays.asList(keytabEntry);
        
        keytab.setEntries(entry);
        
        keytab.write(keytabFile);
      } catch (IOException e) {
        throw new RuntimeException("Could not generate keytab.", e);
      }
      
      return keytabFile;
    }
  }

  private class SSHProviderConfigurer implements ProviderConfigurer {
    @Override
    public SSHConfiguration configure(Provider provider) {
      TestProvider keytabProv = (TestProvider) provider;
      return new SSHConfiguration(PORT, "~/.ssh", keytabProv.generateKeytab().getAbsolutePath(),
          PRINCIPLE, 0);
    }
  }

  @Before
  public void populateBasicKDC() throws Throwable {
    setupEnv(new KnoxObtainTicketParameters(
        TcpTransport.class,
        EncryptionType.DES3_CBC_SHA1, 
        ChecksumType.HMAC_SHA1_DES3));
  }

  @Test
  public void testConnection() throws Throwable {

    ProviderConfigurer configurer = new SSHProviderConfigurer();

    SSHDeploymentContributor deploymentContrib = new SSHDeploymentContributor(
        configurer);

    // start server
    deploymentContrib.contributeProvider(null, new TestProvider());
    
    System.out.println("Started Server.");
    System.out.println("Connecting to server...");

    // set up client
    SshClient client = SshClient.setUpDefaultClient();

    client.start();

    try{
      
      ConnectFuture future = client.connect(USER_UID, HOSTNAME, PORT).await();
      
      ClientSession session = future.getSession();
      
      if(session == null){
        throw new RuntimeException("Could not connect to server", future.getException());
      }
      
      int ret = ClientSession.WAIT_AUTH;
      while ((ret & ClientSession.WAIT_AUTH) != 0) {
        session.authPassword(USER_UID, USER_PASSWORD);
        ret = session.waitFor(ClientSession.WAIT_AUTH | ClientSession.CLOSED
            | ClientSession.AUTHED, 0);
      }
      
      if ((ret & ClientSession.CLOSED) != 0) {
        throw new RuntimeException("Could not connect to server");
      }
      
      ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_EXEC, COMMAND);
      
      channel.setOut(new NoCloseOutputStream(System.out));
      channel.setErr(new NoCloseOutputStream(System.err));
      
      channel.open();
      channel.waitFor(ClientChannel.CLOSED, 0);
      session.close(true); // close imediately
      
    } finally {
      client.stop();
    }
  }

}
