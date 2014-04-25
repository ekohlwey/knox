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
@CreateDS(
    name = "KnoxLDAPPasswordAuthenticatorITest-class", 
    enableChangeLog = false, 
    partitions = { 
        @CreatePartition(
            name = "example", 
            suffix = "dc=example,dc=com", 
            contextEntry = @ContextEntry(
                entryLdif = "dn: dc=example,dc=com\n"
                    + "objectClass: domain\n" + "dc: example")
            ) 
        }
    )
@CreateLdapServer(transports = { @CreateTransport(address = "localhost", protocol = "LDAP", port = 60389) })
@ApplyLdifs({
    // client
    "dn: uid=client,dc=example,dc=com", 
    "objectClass: top",
    "objectClass: person", 
    "objectClass: inetOrgPerson", 
    "cn: client",
    "sn: client", 
    "uid: client",
    "ou: someOU",
    "userPassword: secret"
    })
public class KnoxLDAPAuthorizerITest extends AbstractLdapTestUnit {

  @Test
  public void testAuthorizesValidUserNoGroups() {
    SSHConfiguration configuration = new SSHConfiguration(60389, null, false,
        null, null, -1, "dc=example,dc=com", "uid=client,dc=example,dc=com", "secret", null,
        "ldap://localhost:60389", "cn", null, null, null, false);
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    Assert.assertTrue("User was not authorized",
        authorizer.authorize("client"));
  }
  
  @Test
  public void testAuthorizesValidUserWithGroup() {
    SSHConfiguration configuration = new SSHConfiguration(60389, null, false,
        null, null, -1, "dc=example,dc=com", "uid=client,dc=example,dc=com", "secret", "ou",
        "ldap://localhost:60389", "cn", null, null, new String[]{"someOU"}, false);
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    Assert.assertTrue("User was not authorized",
        authorizer.authorize("client"));
  }
  
  @Test
  public void testAuthorizesValidUserWithMultipleGroups() {
    SSHConfiguration configuration = new SSHConfiguration(60389, null, false,
        null, null, -1, "dc=example,dc=com", "uid=client,dc=example,dc=com", "secret", "ou",
        "ldap://localhost:60389", "cn", null, null, new String[]{"someOU", "anotherOU"}, false);
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    Assert.assertTrue("User was not authorized",
        authorizer.authorize("client"));
  }
  
  @Test
  public void doesntAuthorizeInvalidUser() {
    SSHConfiguration configuration = new SSHConfiguration(60389, null, false,
        null, null, -1, "dc=example,dc=com", "uid=client,dc=example,dc=com", "secret", "ou",
        "ldap://localhost:60389", "cn", null, null, new String[]{"someOU", "anotherOU"}, false);
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    Assert.assertFalse("User was authorized",
        authorizer.authorize("foobar"));
  }
  
  @Test
  public void doesntAuthorizeInvalidUserNoGroups() {
    SSHConfiguration configuration = new SSHConfiguration(60389, null, false,
        null, null, -1, "dc=example,dc=com", "uid=client,dc=example,dc=com", "secret", "ou",
        "ldap://localhost:60389", "cn", null, null, null, false);
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    Assert.assertFalse("User was authorized",
        authorizer.authorize("foobar"));
  }
}
