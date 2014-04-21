package org.apache.hadoop.gateway.ssh;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

import org.apache.commons.io.output.TeeOutputStream;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.kerberos.client.KdcConfig;
import org.apache.directory.kerberos.client.KdcConnection;
import org.apache.directory.kerberos.client.ServiceTicket;
import org.apache.directory.kerberos.client.TgTicket;
import org.apache.directory.kerberos.credentials.cache.Credentials;
import org.apache.directory.kerberos.credentials.cache.CredentialsCache;
import org.apache.directory.server.annotations.CreateChngPwdServer;
import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
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
import org.apache.directory.shared.kerberos.codec.types.PrincipalNameType;
import org.apache.directory.shared.kerberos.components.EncryptionKey;
import org.apache.directory.shared.kerberos.components.PrincipalName;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.kex.DHG1;
import org.apache.sshd.common.KeyExchange;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.util.SecurityUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


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
  
    // client
    "dn: uid=client,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: client",
    "sn: client",
    "uid: client",
    "userPassword: secret",
    "krb5PrincipalName: client@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0",
  
    // ssh
    "dn: uid=ssh,dc=example,dc=com",
    "objectClass: top",
    "objectClass: person",
    "objectClass: inetOrgPerson",
    "objectClass: krb5principal",
    "objectClass: krb5kdcentry",
    "cn: SSH Service",
    "sn: Service",
    "uid: ssh",
    "userPassword: secret",
    "krb5PrincipalName: ssh/localhost@EXAMPLE.COM",
    "krb5KeyVersionNumber: 0",
  
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
 * SSH Deployment Contributor Test
 * 
 * Setting up LDAP, KDC, SSH Provider, and client to test the "help" command
 */
public class SSHDeploymentContributorTest extends AbstractLdapTestUnit {
  
    private static final Logger LOG = LoggerFactory.getLogger(SSHDeploymentContributorTest.class);
  
    public static final String USERS_DN = "dc=example,dc=com";
    public static final String APP_HOST = "localhost";
    public static final Integer APP_PORT = 6091;
    private static String PASSWORD = "secret";
    private static String SSH_UID = "ssh";
    private static String SSH_PRINCIPAL = "ssh/localhost@EXAMPLE.COM";
    private static String CLIENT_UID = "client";
    private static String CLIENT_PRINCIPAL = "client@EXAMPLE.COM";
    
    private static String serverPrincipal;
    private static KdcConnection conn;
    private static File clientKeytab;
    private static File sshKeytab;
    
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Before
    public void setup() throws Throwable {
        kdcServer.setSearchBaseDn( USERS_DN );
        
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
        
        // Generate keytabs
        KeytabGenerator keyGen = new KeytabGenerator();
        clientKeytab = keyGen.generateKeytab(testFolder.newFile("client.keytab"), CLIENT_PRINCIPAL, PASSWORD);
        sshKeytab = keyGen.generateKeytab(testFolder.newFile("ssh.keytab"), SSH_PRINCIPAL, PASSWORD);
    }
    
    private class KeytabGenerator{
      
      public File generateKeytab(File keytabFile, String principalName, String userPassword) throws Throwable {
        
        Keytab keytab = Keytab.getInstance(); 
        KerberosTime timeStamp = new KerberosTime(KerberosUtils.UTC_DATE_FORMAT.parse("20070217235745Z"));

        Map<EncryptionType, EncryptionKey> keys = KerberosKeyFactory
            .getKerberosKeys(principalName, userPassword);
        
        System.out.println("encryption key: " + keys.get(EncryptionType.DES_CBC_MD5).getKeyValue());

        KeytabEntry keytabEntry = new KeytabEntry(
            principalName, 
            1L,
            timeStamp, 
            (byte) 0,
            keys.get(EncryptionType.DES_CBC_MD5));
        
        List<KeytabEntry> entry = Arrays.asList(keytabEntry);
        
        keytab.setEntries(entry);
        
        keytab.write(keytabFile);
        
        return keytabFile;
      }
    }
    

    
    private class TestProvider extends Provider {
      @Override
      public Topology getTopology() {
        Topology topology = new Topology();
        topology.setName("topology");
        return topology;
      }
    }

    private class SSHProviderConfigurer implements ProviderConfigurer {

      @Override
      public SSHConfiguration configure(Provider provider) {
        try {
          return new SSHConfiguration(
              APP_PORT, 
              testFolder.newFile().getAbsolutePath(), 
              sshKeytab.getAbsolutePath(),
              SSH_PRINCIPAL, 0);
        } catch (Throwable e) {
          throw new RuntimeException(e);
        }
      }
    }
    
    public class Kiniter {
      public File kinit(String principal, String password) throws Throwable {
        
        File cCacheFile = testFolder.newFile("ccache");
        
        // Obtain Ticket Granting Ticket
        TgTicket tgt = conn.getTgt(principal, password);
        
        CredentialsCache credCache = new CredentialsCache();
        
        PrincipalName princ = new PrincipalName(principal, PrincipalNameType.KRB_NT_PRINCIPAL);
        princ.setRealm(tgt.getRealm());
        credCache.setPrimaryPrincipalName(princ);
        
        Credentials cred = new Credentials(tgt);
        credCache.addCredentials(cred);
        
        // Obtain Service Ticket
        ServiceTicket serviceTicket = conn.getServiceTicket(principal, password, SSH_PRINCIPAL);
       
        PrincipalName servicePrinc = new PrincipalName(principal, PrincipalNameType.KRB_NT_PRINCIPAL);
        servicePrinc.setRealm(tgt.getRealm());
        
        Credentials servCred = new Credentials(serviceTicket, servicePrinc);
        credCache.addCredentials(servCred);
        
        CredentialsCache.store(cCacheFile, credCache);
        
        return cCacheFile;
      }
    }
    
    class SSHPrivledgedAction implements PrivilegedAction {
      
      public SSHPrivledgedAction() { }

      @Override
      public Object run() {
        
        try {
          SshClient client = SshClient.setUpDefaultClient();
          
          List<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(1);
          userAuthFactories.add(new UserAuthGSS.Factory());
          
          client.setUserAuthFactories(userAuthFactories);
          
          client.setKeyExchangeFactories(Arrays.<NamedFactory<KeyExchange>>asList(
                    new DHG1.Factory()));
          client.start();
          
          ConnectFuture connFuture = client.connect(CLIENT_UID, APP_HOST, APP_PORT).await();
          Assert.assertTrue("Could not connect to server", connFuture.isConnected());
          
          ClientSession session = connFuture.getSession();
          AuthFuture authfuture = session.auth().await();
          Assert.assertTrue("Failed to authenticate to server: " + authfuture.getException(), authfuture.isSuccess());
          
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
        } catch (Exception e) {
          throw new RuntimeException("Failed to ssh into server.", e);
        }
        
        return null;
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
      
      LOG.info("KDC Server info: " + kdcServer.toString());
      
      File ccache = kiniter.kinit(CLIENT_PRINCIPAL, PASSWORD);
      
      // Create new loginConf
      File loginConf = testFolder.newFile("login.conf");
      
      String content = "client {" + 
        " com.sun.security.auth.module.Krb5LoginModule required" + 
        " useTicketCache=true" +
        " ticketCache=\"" + ccache.getAbsolutePath() + "\"" +   
        " debug=true;" + 
      " };";
      
      FileWriter fw = new FileWriter(loginConf.getAbsoluteFile());
      BufferedWriter bw = new BufferedWriter(fw);
      bw.write(content);
      bw.close();
      fw.close();
      
      System.out.println("Wrote login.conf[" + content + "] to file[" + loginConf.getAbsolutePath() + "]");
      
      System.setProperty("java.security.auth.login.config", loginConf.getAbsolutePath());
      
      System.out.println("sendCommand");
      
      LoginContext lc = new LoginContext("client");

      lc.login();

      Subject.doAs(lc.getSubject(), new SSHPrivledgedAction());

    }

}