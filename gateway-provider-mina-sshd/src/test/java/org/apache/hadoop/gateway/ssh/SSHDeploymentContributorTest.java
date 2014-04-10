package org.apache.hadoop.gateway.ssh;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.output.TeeOutputStream;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.kerberos.client.KdcConfig;
import org.apache.directory.kerberos.client.KdcConnection;
import org.apache.directory.kerberos.client.TgTicket;
import org.apache.directory.server.annotations.CreateChngPwdServer;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.kerberos.kdc.KerberosTestUtils;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.apache.directory.server.kerberos.shared.keytab.KeytabEntry;
import org.apache.directory.shared.kerberos.KerberosTime;
import org.apache.directory.shared.kerberos.KerberosUtils;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.util.SecurityUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateDS(name = "KdcConnectionTest-class", enableChangeLog = false,
    partitions =
        {
            @CreatePartition(
                name = "example",
                suffix = "dc=example,dc=com",
                contextEntry=@ContextEntry( entryLdif = 
                    "dn: dc=example,dc=com\n" +
                    "objectClass: domain\n" +
                    "dc: example" ) )
    },
    additionalInterceptors =
        {
            KeyDerivationInterceptor.class
    })
@CreateLdapServer(
    transports =
        {
            @CreateTransport(address="localhost", protocol = "LDAP")
    })
@CreateKdcServer(
    searchBaseDn = "dc=example,dc=com",
    transports =
        {
            @CreateTransport(address="localhost", protocol = "TCP", port = 6089),
            @CreateTransport(protocol = "UDP")
    },
    chngPwdServer = @CreateChngPwdServer
    (
        transports =
        {
            @CreateTransport(address="localhost", protocol = "TCP", port = 6090),
            @CreateTransport(protocol = "UDP")
        }    
    ))
@ApplyLdifs({
    // krbtgt
    "dn: uid=krbtgt,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: KDC Service",
    "sn: Service",
    "uid: krbtgt",
    "userPassword: secret",
    "krb5PrincipalName: krbtgt/EXAMPLE.COM@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0",
    
    // changepwd
    "dn: uid=kadmin,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: changepw Service",
    "sn: Service",
    "uid: kadmin",
    "userPassword: secret",
    "krb5PrincipalName: kadmin/changepw@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0",

    // app service
    "dn: uid=ldap,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: LDAP",
    "sn: Service",
    "uid: ldap",
    "userPassword: randall",
    "krb5PrincipalName: ldap/localhost@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0"
})
/**
 * KDC connection tests
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SSHDeploymentContributorTest extends AbstractLdapTestUnit
{
    public static final String USERS_DN = "dc=example,dc=com";
    public static final String APP_HOST = "localhost";
    public static final Integer APP_PORT = 6091;
    public static final String REALM = "EXAMPLE.COM";
    
    private static CoreSession session;
    private static KdcConnection conn;
    private static String userPassword = "secret";
    private static String userUid = "josh";
    private static String principalName = userUid + "@" + REALM;
    private static String serverPrincipal;

    @Before
    public void setup() throws Exception
    {
        kdcServer.setSearchBaseDn( USERS_DN );
        if ( session == null )
        {
            session = kdcServer.getDirectoryService().getAdminSession();
            createPrincipal( userUid, userPassword, principalName );
        }
        
        if ( conn == null )
        {
            KdcConfig config = KdcConfig.getDefaultConfig();
            config.setUseUdp( false );
            config.setKdcPort( kdcServer.getTcpPort() );
            config.setPasswdPort( kdcServer.getChangePwdServer().getTcpPort() );
            config.setEncryptionTypes( kdcServer.getConfig().getEncryptionTypes() );
            config.setTimeout( Integer.MAX_VALUE );
            conn = new KdcConnection( config );
        }
        if ( serverPrincipal == null )
        {
            serverPrincipal = KerberosTestUtils.fixServicePrincipalName( "ldap/localhost@EXAMPLE.COM", new Dn(
                "uid=ldap,dc=example,dc=com" ), getLdapServer() );
        }
    }
    
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();
    
    private class TestProvider extends Provider {
      
      @Override
      public Topology getTopology() {
        Topology topology = new Topology();
        topology.setName("topology");
        return topology;
      }

      public File generateKeytab(File keytabFile) throws Throwable {
        
        Keytab keytab = Keytab.getInstance(); 
        
        KerberosTime timeStamp = new KerberosTime(KerberosUtils.UTC_DATE_FORMAT.parse("20070217235745Z"));

        Map<EncryptionType, EncryptionKey> keys = KerberosKeyFactory
            .getKerberosKeys(principalName, userPassword);

        KeytabEntry keytabEntry = new KeytabEntry(
            principalName, 
            1L,
            timeStamp, 
            (byte) 1, 
            keys.get(EncryptionType.DES_CBC_MD5));
        
        List<KeytabEntry> entry = Arrays.asList(keytabEntry);
        
        keytab.setEntries(entry);
        
        keytab.write(keytabFile);
        
        System.out.println("Wrote keytab file to " + keytabFile.getAbsolutePath());
        
        return keytabFile;
      }
    }

    private class SSHProviderConfigurer implements ProviderConfigurer {
      
      private File keytabFile;

      public SSHProviderConfigurer() throws Throwable{
        keytabFile = testFolder.newFile(userUid + ".keytab");
      }

      @Override
      public SSHConfiguration configure(Provider provider) {
        TestProvider keytabProv = (TestProvider) provider;
        try {
          return new SSHConfiguration(
              APP_PORT, 
              testFolder.newFile().getAbsolutePath(), 
              keytabProv.generateKeytab(keytabFile).getAbsolutePath(),
              principalName, 0);
        } catch (Throwable e) {
          throw new RuntimeException(e);
        }
      }
      
      public File getKeytabFile() {
        return keytabFile;
      }
    }
    
    public class Kiniter {
      public void kinit(File keytabFile) throws Throwable {

        TgTicket ticket = conn.getTgt(principalName, userPassword);
        
        Assert.assertNotNull("Failed to aquire ticket.", ticket);
      }
    }
    
    @Test
    public void testConnection() throws Throwable {

      Kiniter kiniter = new Kiniter();
      SSHProviderConfigurer configurer = new SSHProviderConfigurer();

      SecurityUtils.setRegisterBouncyCastle(false); // must disable BC to get ciphers to work.
      
      SSHDeploymentContributor deploymentContrib = new SSHDeploymentContributor(
          configurer);

      // start server
      deploymentContrib.contributeProvider(null, new TestProvider());
      
      System.out.println("KDC Server info: " + kdcServer.toString());
      
      File keytabFile = configurer.getKeytabFile();
      kiniter.kinit(keytabFile);
      
//      while(true) { ; }
      
      SshClient client = SshClient.setUpDefaultClient();
      client.start();
      
      ConnectFuture connFuture = client.connect(APP_HOST, APP_PORT).await();
      Assert.assertTrue("Could not connect to server", connFuture.isConnected());
      
      ClientSession session = connFuture.getSession();
      AuthFuture authfuture = session.authPassword(userUid, userPassword).await();
      Assert.assertTrue("Failed to authenticate to server: " + authfuture.getException().toString(), authfuture.isSuccess());
      
      ClientChannel channel = session.createChannel(ClientChannel.CHANNEL_SHELL);

      ByteArrayOutputStream sent = new ByteArrayOutputStream();
      PipedOutputStream pipedIn = new PipedOutputStream();
      channel.setIn(new PipedInputStream(pipedIn));
      OutputStream teeOut = new TeeOutputStream(sent, pipedIn);
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      ByteArrayOutputStream err = new ByteArrayOutputStream();
      channel.setOut(out);
      channel.setErr(err);
      channel.open();

      teeOut.write("help\n".getBytes());
      teeOut.flush();
      teeOut.close();

      channel.waitFor(ClientChannel.CLOSED, 0); // technically this will never work, we need an exit action :)

      channel.close(false);
      client.stop();
      
      Assert.assertTrue("Did not receive output", out.toByteArray().length > 0);
    }
    
    private String createPrincipal( String uid, String userPassword, String principalName ) throws Exception {
        Entry entry = new DefaultEntry( session.getDirectoryService().getSchemaManager() );
        entry.setDn( "uid=" + uid + "," + USERS_DN );
        entry.add( "objectClass", "top", "person", "inetOrgPerson", "krb5principal", "krb5kdcentry" );
        entry.add( "cn", uid );
        entry.add( "sn", uid );
        entry.add( "uid", uid );
        entry.add( "userPassword", userPassword );
        entry.add( "krb5PrincipalName", principalName );
        entry.add( "krb5KeyVersionNumber", "0" );
        session.add( entry );
        
        return entry.getDn().getName();
    }

}