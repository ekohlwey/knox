package org.apache.hadoop.gateway.ssh;

import org.apache.directory.api.ldap.model.exception.LdapURLEncodingException;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;

public class LDAPConnectionFactory {

  public static class InvalidURLException extends Exception {

    private static final long serialVersionUID = 1L;

    public InvalidURLException(Throwable source) {
      super(source);
    }
  }

  public LdapConnection createConnection(String urlString)
      throws InvalidURLException {
    LdapUrl url;
    try {
      url = new LdapUrl(urlString);
    } catch (LdapURLEncodingException e) {
      throw new InvalidURLException(e);
    }
    return new LdapNetworkConnection(url.getHost(), url.getPort(), url
        .getScheme().startsWith("ldaps"));
  }

}
