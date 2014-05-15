package org.apache.hadoop.gateway.ssh.auth;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.shiro.realm.ldap.LdapUtils;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KnoxLDAPPasswordAuthenticator implements PasswordAuthenticator {

  private static final Logger LOG = LoggerFactory
      .getLogger(KnoxLDAPPasswordAuthenticator.class);

  private final SSHConfiguration configuration;
  private final LDAPEscaper escaper;
  private final LDAPAuthorizer authorizer;

  private final JndiLdapContextFactory connectionFactory;

  public KnoxLDAPPasswordAuthenticator(SSHConfiguration configuration) {
    this(configuration, new LDAPEscaper(), new LDAPAuthorizer(configuration),
        new JndiLdapContextFactory());
  }

  public KnoxLDAPPasswordAuthenticator(SSHConfiguration configuration,
      LDAPEscaper ldapEscaper, LDAPAuthorizer authorizer,
      JndiLdapContextFactory connectionFactory) {
    this.configuration = configuration;
    this.escaper = ldapEscaper;
    this.authorizer = authorizer;
    this.connectionFactory = connectionFactory;
  }

  @Override
  public boolean authenticate(String username, String password,
      ServerSession session) {
    username = escaper.escape(username);
    if (!authorizer.authorize(username)) {
      return false;
    }
    String authenticationUrl = configuration.getAuthenticationURL();
    if (authenticationUrl == null) {
      authenticationUrl = configuration.getAuthorizationURL();
    }
    LdapContext context = null;
    try {
      String fullUsername = configuration.getAuthenticationPattern().replace("{0}",
          username);
      //check if user can connect with user/pwd
      context = connectionFactory
          .createContext(authenticationUrl, fullUsername, password);
      return true;
    } catch (NamingException e) {
      return false;
    } finally {
      if(context != null) {
        LdapUtils.closeContext(context);
      }
    }
  }

}
