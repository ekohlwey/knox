package org.apache.hadoop.gateway.ssh;

import java.io.IOException;
import java.net.MalformedURLException;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LDAPAuthorizer {

  private final LDAPEscaper escaper;
  private final SSHConfiguration configuration;
  private static final Logger LOG = LoggerFactory
      .getLogger(LDAPAuthorizer.class);

  public LDAPAuthorizer(SSHConfiguration configuration, LDAPEscaper escaper) {
    this.configuration = configuration;
    this.escaper = escaper;
  }

  public LDAPAuthorizer(SSHConfiguration configuration) {
    this(configuration, new LDAPEscaper());
  }

  public boolean authorize(String username) {
    LdapConnection connection = null;
    EntryCursor cursor = null;
    try {
      LdapUrl url = new LdapUrl(configuration.getAuthorizationURL());
      connection = new LdapNetworkConnection(url.getHost(), url.getPort(), url
          .getScheme().equals("ldaps"));
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
    } finally {
      try {
        if (cursor != null) {
          cursor.close();
        }
      } finally {
        try {
          if (connection != null) {
            connection.unBind();
          }
        } catch (LdapException e) {
          LOG.error("Unable to unbind from LDAP", e);
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
    }
    return true;
  }

}
