package org.apache.hadoop.gateway.ssh.auth;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

/**
 *
 */
public class JndiLdapContextFactory {

  public LdapContext createContext(String url, String principal, String credentials)
      throws NamingException {
    Hashtable<String, Object> env = new Hashtable<String, Object>();

    env.put(Context.SECURITY_AUTHENTICATION, "simple");
    if (principal != null) {
      env.put(Context.SECURITY_PRINCIPAL, principal);
    }
    if (credentials!= null) {
      env.put(Context.SECURITY_CREDENTIALS, credentials);
    }
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, url);
    env.put(Context.REFERRAL, "follow");

    return new InitialLdapContext(env, null);
  }
}
