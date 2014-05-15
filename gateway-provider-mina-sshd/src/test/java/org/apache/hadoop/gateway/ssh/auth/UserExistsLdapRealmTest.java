package org.apache.hadoop.gateway.ssh.auth;

import static org.junit.Assert.*;

import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Test;

public class UserExistsLdapRealmTest {

  @Test
  public void testUserExists() throws Exception {

    String searchBase = "ou=people,dc=example,dc=com";
    String username = "user";

    Capture<Object[]> userCapture = new Capture<Object[]>();

    LdapContextFactory ldapContextFactory =
        EasyMock.createMock(LdapContextFactory.class);
    LdapContext ldapContext = EasyMock.createMock(LdapContext.class);
    NamingEnumeration<SearchResult> search =
        EasyMock.createMock(NamingEnumeration.class);
    EasyMock.expect(ldapContextFactory.getSystemLdapContext())
        .andReturn(ldapContext);
    EasyMock.expect(ldapContext.search(EasyMock.eq(searchBase),
        EasyMock.eq("(&(objectClass=*)(uid={0}))"),
        EasyMock.capture(userCapture),
        EasyMock.anyObject(SearchControls.class))).andReturn(search);
    EasyMock.expect(search.hasMoreElements()).andReturn(true);
    search.close();
    EasyMock.expectLastCall();

    EasyMock.replay(ldapContextFactory, ldapContext, search);

    UserExistsLdapRealm userExistsLdapRealm = new UserExistsLdapRealm();
    userExistsLdapRealm.setSearchBase(searchBase);
    userExistsLdapRealm.setLdapContextFactory(ldapContextFactory);
    AuthenticationInfo authenticationInfo = userExistsLdapRealm
        .getAuthenticationInfo(
            new UsernamePasswordToken("username", "doesnotmatter"));
    assertNotNull(authenticationInfo);

    EasyMock.verify(ldapContextFactory, ldapContext, search);
  }

  @Test(expected = AuthenticationException.class)
  public void testUserDoesNotExist() throws Exception {

    String searchBase = "ou=people,dc=example,dc=com";
    String username = "user";

    Capture<Object[]> userCapture = new Capture<Object[]>();

    LdapContextFactory ldapContextFactory =
        EasyMock.createMock(LdapContextFactory.class);
    LdapContext ldapContext = EasyMock.createMock(LdapContext.class);
    NamingEnumeration<SearchResult> search =
        EasyMock.createMock(NamingEnumeration.class);
    EasyMock.expect(ldapContextFactory.getSystemLdapContext())
        .andReturn(ldapContext);
    EasyMock.expect(ldapContext.search(EasyMock.eq(searchBase),
        EasyMock.eq("(&(objectClass=*)(uid={0}))"),
        EasyMock.capture(userCapture), EasyMock.anyObject(SearchControls.class))).andReturn(
        search);
    EasyMock.expect(search.hasMoreElements()).andReturn(false);
    search.close();
    EasyMock.expectLastCall();

    EasyMock.replay(ldapContextFactory, ldapContext, search);

    UserExistsLdapRealm userExistsLdapRealm = new UserExistsLdapRealm();
    userExistsLdapRealm.setSearchBase(searchBase);
    userExistsLdapRealm.setLdapContextFactory(ldapContextFactory);
    userExistsLdapRealm
        .getAuthenticationInfo(
            new UsernamePasswordToken("username", "doesnotmatter"));

    EasyMock.verify(ldapContextFactory, ldapContext, search);
  }

}