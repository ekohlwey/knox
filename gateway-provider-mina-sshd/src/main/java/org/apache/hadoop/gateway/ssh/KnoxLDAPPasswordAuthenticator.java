package org.apache.hadoop.gateway.ssh;

import java.io.IOException;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.hadoop.gateway.ssh.LDAPConnectionFactory.InvalidURLException;
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

  private LDAPConnectionFactory connectionFactory;

  public KnoxLDAPPasswordAuthenticator(SSHConfiguration configuration) {
    this(configuration, new LDAPEscaper(), new LDAPAuthorizer(configuration),
        new LDAPConnectionFactory());
  }

  public KnoxLDAPPasswordAuthenticator(SSHConfiguration configuration,
      LDAPEscaper ldapEscaper, LDAPAuthorizer authorizer,
      LDAPConnectionFactory connectionFactory) {
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
    LdapConnection connection = null;
    String authenticationUrl = configuration.getAuthenticationURL();
    if (authenticationUrl == null) {
      authenticationUrl = configuration.getAuthorizationURL();
    }
    try {

      String bindName = configuration.getAuthenticationPattern().replace("{0}",
          username);
      connection = connectionFactory.createConnection(authenticationUrl);
      connection.bind(bindName, password);
      return true;
    } catch (LdapException e) {
      return false;
    } catch (InvalidURLException e) {
      LOG.error(
          "Incorrect authentication url configuration: " + authenticationUrl
              + ". Nobody will be able to authenticate via LDAP.", e);
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
