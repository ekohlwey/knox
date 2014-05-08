package org.apache.hadoop.gateway.ssh.auth;

import java.io.IOException;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.hadoop.gateway.ssh.auth.LDAPConnectionFactory.InvalidURLException;
import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LDAPAuthorizer {

  private final LDAPEscaper escaper;
  private final SSHConfiguration configuration;
  private final LDAPConnectionFactory connectionFactory;
  private static final Logger LOG = LoggerFactory
      .getLogger(LDAPAuthorizer.class);

  public LDAPAuthorizer(SSHConfiguration configuration, LDAPEscaper escaper,
      LDAPConnectionFactory ldapConnectionFactory) {
    this.configuration = configuration;
    this.escaper = escaper;
    this.connectionFactory = ldapConnectionFactory;
  }

  public LDAPAuthorizer(SSHConfiguration configuration) {
    this(configuration, new LDAPEscaper(), new LDAPConnectionFactory());
  }

  public boolean authorize(String username) {
    LdapConnection connection = null;
    EntryCursor cursor = null;
    try {
      connection = connectionFactory.createConnection(configuration
          .getAuthorizationURL());
      connection.bind(configuration.getAuthorizationUser(),
          configuration.getAuthorizationPass());
      StringBuilder queryString = new StringBuilder();
      // open and
      // open name attr == name
      queryString.append("(&(");
      queryString.append(escaper.escape(configuration
          .getAuthorizationNameAttribute()));
      queryString.append("=");
      queryString.append(escaper.escape(username));
      // close name attr ==
      queryString.append(")");
      String[] groupIds = configuration.getAuthorizationGroupIds();
      if (groupIds != null && groupIds.length > 0) {
        // open or
        queryString.append("(|");
        for (String groupValue : groupIds) {
          // open group ==
          queryString.append("(");
          queryString.append(escaper.escape(configuration
              .getAuthorizationGroupAttribute()));
          queryString.append("=");
          queryString.append(escaper.escape(groupValue));
          // close group ==
          queryString.append(")");
        }
        // close or
        queryString.append(")");
      }
      // close and
      queryString.append(")");
      cursor = connection.search(configuration.getAuthorizationBase(),
          queryString.toString(), SearchScope.SUBTREE,
          escaper.escape(configuration.getAuthorizationNameAttribute()));
      if (!cursor.next()) {
        return false;
      }
    } catch (LdapException e) {
      LOG.error("Unable to connect to or contact LDAP", e);
      return false;
    } catch (CursorException e) {
      LOG.error("Unable to read from LDAP", e);
      return false;
    } catch (InvalidURLException e) {
      LOG.error("Invalid LDAP URI in configuration: "
          + configuration.getAuthorizationURL()
          + ". Nobody will be authorized to connect, even if authenticated.");
      return false;
    } finally {
      try {
        if (cursor != null) {
          cursor.close();
        }
      } finally {
        try {
          if (connection != null) {
            connection.close();
          }
        } catch (IOException e) {
          LOG.error("IO exception disconnecting from LDAP", e);
        }
      }
    }
    return true;
  }

}
