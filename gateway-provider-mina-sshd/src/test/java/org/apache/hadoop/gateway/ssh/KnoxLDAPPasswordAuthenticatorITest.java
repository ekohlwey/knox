package org.apache.hadoop.gateway.ssh;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.junit.Assert;
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

    SSHConfiguration configuration = new SSHConfiguration(0, null, false, null,
        null, 0, null, null, null, null, null, null, "ldap://localhost:60389",
        "uid={0},dc=example,dc=com", null, true);
    
    KnoxLDAPPasswordAuthenticator pa = new KnoxLDAPPasswordAuthenticator(
        configuration, new LDAPEscaper(), alwaysAuthorizer);
    Assert.assertTrue("User was not able to authenticate via bind.",
        pa.authenticate("client", "secret", null));

  }
  
  @Test
  public void doesntAuthenticateInvalidUser() {

    SSHConfiguration configuration = new SSHConfiguration(0, null, false, null,
        null, 0, null, null, null, null, null, null, "ldap://localhost:60389",
        "uid={0},dc=example,dc=com", null, true);
    
    KnoxLDAPPasswordAuthenticator pa = new KnoxLDAPPasswordAuthenticator(
        configuration, new LDAPEscaper(), alwaysAuthorizer);
    Assert.assertTrue("User was able to authenticate via bind.",
        pa.authenticate("client", "dsflkjsdf", null));

  }
}
