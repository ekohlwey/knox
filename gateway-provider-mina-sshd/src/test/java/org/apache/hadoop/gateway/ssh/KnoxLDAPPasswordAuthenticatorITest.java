package org.apache.hadoop.gateway.ssh;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateDS(name = "KnoxLDAPPasswordAuthenticatorITest-class", enableChangeLog = false, partitions = { @CreatePartition(name = "example", suffix = "dc=example,dc=com", contextEntry = @ContextEntry(entryLdif = "dn: dc=example,dc=com\n"
    + "objectClass: domain\n" + "dc: example")) })
@CreateLdapServer(transports = { @CreateTransport(address = "localhost", protocol = "LDAP", port = 60389) })
@ApplyLdifs({
    // client
    "dn: uid=client,dc=example,dc=com", "objectClass: top",
    "objectClass: person", "objectClass: inetOrgPerson", "cn: client",
    "sn: client", "uid: client", "ou: someOU", "userPassword: secret" })
public class KnoxLDAPPasswordAuthenticatorITest extends AbstractLdapTestUnit {

  private final LDAPAuthorizer alwaysAuthorizer = new LDAPAuthorizer(null) {
    @Override
    public boolean authorize(String username) {
      return true;
    }
  };

  @Test
  public void authenticatesValidUser() {

    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthenticationPattern("uid={0},dc=example,dc=com");
    configuration.setAuthenticationURL("ldap://localhost:60389");
    
    KnoxLDAPPasswordAuthenticator pa = new KnoxLDAPPasswordAuthenticator(
        configuration, new LDAPEscaper(), alwaysAuthorizer, new LDAPConnectionFactory());
    assertTrue("User was not able to authenticate via bind.",
        pa.authenticate("client", "secret", null));

  }
  
  @Test
  public void doesntAuthenticateInvalidPassword() {

    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthenticationPattern("uid={0},dc=example,dc=com");
    configuration.setAuthenticationURL("ldap://localhost:60389");
    
    KnoxLDAPPasswordAuthenticator pa = new KnoxLDAPPasswordAuthenticator(
        configuration, new LDAPEscaper(), alwaysAuthorizer, new LDAPConnectionFactory());
    assertFalse("User was able to authenticate via bind.",
        pa.authenticate("client", "dsflkjsdf", null));

  }
  
  @Test
  public void doesntAuthenticateInvalidUser() {
    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthenticationPattern("uid={0},dc=example,dc=com");
    configuration.setAuthenticationURL("ldap://localhost:60389");
    
    KnoxLDAPPasswordAuthenticator pa = new KnoxLDAPPasswordAuthenticator(
        configuration, new LDAPEscaper(), alwaysAuthorizer, new LDAPConnectionFactory());
    assertFalse("User was able to authenticate via bind.",
        pa.authenticate("sdafdsaf", "dsflkjsdf", null));
  }
}
