package org.apache.hadoop.gateway.ssh;

import java.util.Map;

import org.apache.hadoop.gateway.topology.Provider;

public class ProviderConfigurer {

  public static final String SSH_PORT = "port";
  public static final String SSH_FINGERPRINT_LOCATION = "ssh-fingerprint-location";
  public static final String KEYTAB_LOCATION = "keytab";
  public static final String PROVIDER_PRINCIPAL = "kerberos-principal";
  public static final String WORKERS = "workers";
  public static final String KERBEROS_ENABLED = "kerberos-enabled";
  public static final String LDAP_AUTHORIZATION_URL = "ldap-authorization-url";
  public static final String LDAP_AUTHORIZATION_BASE_DN = "ldap-authorization-base";
  public static final String LDAP_AUTHORIZATION_USER = "ldap-authorization-user";
  public static final String LDAP_AUTHORIZATION_PASSWORD = "ldap-authorization-password";
  public static final String LDAP_AUTHORIZATION_ATTRIBUTE = "ldap-authorization-member-attribute";
  public static final String LDAP_AUTHORIZATION_NAME_ATTRIBUTE = "ldap-authorization-username-attribute";
  public static final String LDAP_AUTHENTICATION_URL = "ldap-authentication-url";
  public static final String LDAP_AUTHENTICATION_NAME_PATTERN = "ldap-bind-pattern";
  public static final String LDAP_AUTHORIZATION_GROUP_IDS = "ldap-authorization-groups";
  public static final String LDAP_AUTHENTICATION_ENABLED = "ldap-authentication-enabled";
  public static final String TRUE = "true";

  public SSHConfiguration configure(Provider provider) {
    Map<String, String> providerParams = provider.getParams();
    // ssh port not optional
    int port = Integer.parseInt(providerParams.get(SSH_PORT));
    // ssh fingerprint -> has default
    String sshLocation = providerParams.get(SSH_FINGERPRINT_LOCATION);
    if (sshLocation == null) {
      sshLocation = "/var/run/knox/ssh.fingerprint";
    }
    // use kerberos -> default is false
    String useKerberosStr = providerParams.get(KERBEROS_ENABLED);
    String servicePrincipal = null;
    String keytabLocation = null;
    boolean useKerberos = false;
    if (useKerberos = (useKerberosStr != null && useKerberosStr.equals(TRUE))) {
      // keytab location -> has default
      keytabLocation = providerParams.get(KEYTAB_LOCATION);
      if (keytabLocation == null) {
        keytabLocation = "/etc/knox/conf/knox.service.keytab";
      }
      // principal -> not optional if kerberos is on
      servicePrincipal = providerParams.get(PROVIDER_PRINCIPAL);
    }
    // workers -> optional
    String workersString = providerParams.get(WORKERS);
    int workers;
    if (workersString != null) {
      workers = Integer.parseInt(workersString);
    } else {
      workers = -1;
    }
    // ldap authorization base DN -> no default
    String authorizationBase = providerParams.get(LDAP_AUTHORIZATION_BASE_DN);
    String authorizationUser = providerParams.get(LDAP_AUTHORIZATION_USER);
    String authorizationPass = providerParams.get(LDAP_AUTHORIZATION_PASSWORD);
    String authorizationGroupAttribute = providerParams
        .get(LDAP_AUTHORIZATION_ATTRIBUTE);
    String authorizationURL = providerParams.get(LDAP_AUTHORIZATION_URL);
    String authorizationNameAttribute = providerParams
        .get(LDAP_AUTHORIZATION_NAME_ATTRIBUTE);
    String[] authorizationGroups = providerParams.get(
        LDAP_AUTHORIZATION_GROUP_IDS).split(";");
    String ldapEnabledString = providerParams.get(LDAP_AUTHENTICATION_ENABLED);
    boolean ldapEnabled = ldapEnabledString == null
        || ldapEnabledString.toLowerCase().equals(TRUE);
    String authenticationURL = null;
    String authPattern = null;
    if (ldapEnabled) {
      authenticationURL = providerParams.get(LDAP_AUTHENTICATION_URL);
      authPattern = providerParams.get(LDAP_AUTHENTICATION_NAME_PATTERN);
    }

    return new SSHConfiguration(port, sshLocation, useKerberos, keytabLocation,
        servicePrincipal, workers, authorizationBase, authorizationUser,
        authorizationPass, authorizationGroupAttribute, authorizationURL,
        authorizationNameAttribute, authenticationURL, authPattern,
        authorizationGroups, ldapEnabled);
  }
}
