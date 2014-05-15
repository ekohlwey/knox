package org.apache.hadoop.gateway.ssh.auth;

import javax.naming.AuthenticationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapContext;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.ldap.AbstractLdapRealm;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Will only authenticate if the user exists in LDAP
 */
public class UserExistsLdapRealm extends AbstractLdapRealm {
  private static Logger LOG =
      LoggerFactory.getLogger(UserExistsLdapRealm.class);

  private static final SearchControls SUBTREE_CTLS = new SearchControls();

  static {
    SUBTREE_CTLS.setSearchScope(SearchControls.SUBTREE_SCOPE);
  }

  private String userSearchFilter = "(&(objectClass=*)(uid={0}))";

  public String getUserSearchFilter() {
    return userSearchFilter;
  }

  public void setUserSearchFilter(String userSearchFilter) {
    this.userSearchFilter = userSearchFilter;
  }

  @Override
  protected AuthenticationInfo queryForAuthenticationInfo(
      AuthenticationToken token, LdapContextFactory ldapContextFactory)
      throws NamingException {
    UsernamePasswordToken upToken = (UsernamePasswordToken) token;

    // Binds using the username and password provided by the user.
    LdapContext ctx = null;
    NamingEnumeration<SearchResult> search = null;
    try {
      ctx = ldapContextFactory.getSystemLdapContext();

      //check if user dn exists
      String username = upToken.getUsername();
      Object[] searchArguments = new Object[]{username};
      search = ctx.search(searchBase, userSearchFilter, searchArguments,
          SUBTREE_CTLS);
      if (!search.hasMoreElements()) {
        throw new AuthenticationException(
            "Authentication failed for user[" + username + "]");
      }
    } finally {
      LdapUtils.closeEnumeration(search);
    }

    return buildAuthenticationInfo(upToken.getUsername(),
        upToken.getPassword());
  }

  protected AuthenticationInfo buildAuthenticationInfo(String username,
                                                       char[] password) {
    return new SimpleAuthenticationInfo(username, password, getName());
  }

  @Override
  protected AuthorizationInfo queryForAuthorizationInfo(
      PrincipalCollection principal, LdapContextFactory ldapContextFactory)
      throws NamingException {
    //no authorization implementation
    return null;
  }
}
