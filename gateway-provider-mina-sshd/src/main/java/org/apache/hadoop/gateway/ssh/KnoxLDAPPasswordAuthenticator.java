package org.apache.hadoop.gateway.ssh;

import java.io.IOException;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
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

  public KnoxLDAPPasswordAuthenticator(SSHConfiguration configuration) {
    this(configuration, new LDAPEscaper(), new LDAPAuthorizer(configuration));
  }

  public KnoxLDAPPasswordAuthenticator(SSHConfiguration configuration,
      LDAPEscaper ldapEscaper, LDAPAuthorizer authorizer) {
    this.configuration = configuration;
    this.escaper = ldapEscaper;
    this.authorizer = authorizer;
  }

  @Override
  public boolean authenticate(String username, String password,
      ServerSession session) {
    if (!authorizer.authorize(username)) {
      return false;
    }
    LdapConnection connection = null;
    try {
      String authenticationUrl = configuration.getAuthenticationURL();
      if (authenticationUrl == null) {
        authenticationUrl = configuration.getAuthorizationURL();
      }
      LdapUrl url = new LdapUrl(authenticationUrl);
      String bindName = configuration.getAuthenticationPattern().replace("{0}",
          username);
      connection = new LdapNetworkConnection(url.getHost(), url.getPort(), url.getScheme().startsWith("ldaps"));
      connection.bind(bindName, password);
      return true;
    } catch (LdapException e) {
      return false;
    } finally {
      if (connection != null) {
        try {
          connection.close();
        } catch (IOException e) {
          LOG.error("Error closing LDAP connection", e);
        }
      }
    }
  }

}
