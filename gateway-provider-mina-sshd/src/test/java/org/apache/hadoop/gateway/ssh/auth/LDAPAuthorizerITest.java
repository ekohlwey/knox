package org.apache.hadoop.gateway.ssh.auth;

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
import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.auth.LDAPAuthorizer;
import org.apache.hadoop.test.category.IntegrationTests;
import org.junit.Test;
import org.junit.experimental.categories.Category;
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
public class LDAPAuthorizerITest extends AbstractLdapTestUnit {

  @Test
  public void testAuthorizesValidUserNoGroups() {
    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthorizationBase("dc=example,dc=com");
    configuration.setAuthorizationUser("uid=client,dc=example,dc=com");
    configuration.setAuthorizationPass("secret");
    configuration.setAuthorizationURL("ldap://localhost:60389");
    configuration.setAuthorizationNameAttribute("cn");
    
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    assertTrue("User was not authorized",
        authorizer.authorize("client"));
  }
  
  @Test
  public void testAuthorizesValidUserWithGroup() {
    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthorizationBase("dc=example,dc=com");
    configuration.setAuthorizationUser("uid=client,dc=example,dc=com");
    configuration.setAuthorizationPass("secret");
    configuration.setAuthorizationURL("ldap://localhost:60389");
    configuration.setAuthorizationNameAttribute("cn");
    configuration.setAuthorizationGroupIds(new String[]{"someOU"});
    configuration.setAuthorizationGroupAttribute("ou");
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    assertTrue("User was not authorized",
        authorizer.authorize("client"));
  }
  
  @Test
  public void testAuthorizesValidUserWithMultipleAllowedGroups() {
    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthorizationBase("dc=example,dc=com");
    configuration.setAuthorizationUser("uid=client,dc=example,dc=com");
    configuration.setAuthorizationPass("secret");
    configuration.setAuthorizationURL("ldap://localhost:60389");
    configuration.setAuthorizationNameAttribute("cn");
    configuration.setAuthorizationGroupIds(new String[]{"someOU", "anotherOU"});
    configuration.setAuthorizationGroupAttribute("ou");
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    assertTrue("User was not authorized",
        authorizer.authorize("client"));
  }
  
  @Test
  public void doesntAuthorizeInvalidUser() {
    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthorizationBase("dc=example,dc=com");
    configuration.setAuthorizationUser("uid=client,dc=example,dc=com");
    configuration.setAuthorizationPass("secret");
    configuration.setAuthorizationURL("ldap://localhost:60389");
    configuration.setAuthorizationNameAttribute("cn");
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    assertFalse("User was authorized",
        authorizer.authorize("foobar"));
  }
  
  @Test
  public void doesntAuthorizeInvalidUserNoGroups() {
    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthorizationBase("dc=example,dc=com");
    configuration.setAuthorizationUser("uid=client,dc=example,dc=com");
    configuration.setAuthorizationPass("secret");
    configuration.setAuthorizationURL("ldap://localhost:60389");
    configuration.setAuthorizationNameAttribute("cn");
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    assertFalse("User was authorized",
        authorizer.authorize("foobar"));
  }
  
  @Test
  public void doesntAuthorizeValidUserInvalidGroup() {
    SSHConfiguration configuration = new SSHConfiguration();
    configuration.setAuthorizationBase("dc=example,dc=com");
    configuration.setAuthorizationUser("uid=client,dc=example,dc=com");
    configuration.setAuthorizationPass("secret");
    configuration.setAuthorizationURL("ldap://localhost:60389");
    configuration.setAuthorizationNameAttribute("cn");
    configuration.setAuthorizationGroupIds(new String[]{"notTheGroupTheUserHas"});
    configuration.setAuthorizationGroupAttribute("ou");
    LDAPAuthorizer authorizer = new LDAPAuthorizer(configuration);
    assertFalse("User was authorized",
        authorizer.authorize("client"));
  }
}
