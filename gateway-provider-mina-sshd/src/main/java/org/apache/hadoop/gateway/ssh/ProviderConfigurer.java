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
  public static final String SHIRO_AUTHENTICATION_ENABLED = "shiro-authentication-enabled";
  public static final String TRUE = "true";
  public static final String TUNNEL_KEYFILE = "tunnel-keyfile";
  public static final String TUNNEL_USER = "tunnel-user";
  public static final String TUNNEL_TIMEOUT = "tunnel-timeout";
  public static final String LOGIN_COMMAND ="login-command";
  public static final String STREAM_FLUSH_PERIOD ="stream-flush-period";
  public static final String SESSION_IDLE_TIMEOUT ="session-idle-timeout";
  public static final Integer DEFAULT_QUEUE_SIZE = 1024;
  public static final Integer DEFAULT_STREAM_FLUSH_PERIOD = 50;

  public SSHConfiguration configure(Provider provider) {
    Map<String, String> providerParams = provider.getParams();

    //check enabled auths
    boolean useKerberos = TRUE.equalsIgnoreCase(providerParams.get(KERBEROS_ENABLED));
    boolean ldapEnabled = TRUE.equalsIgnoreCase(providerParams.get(LDAP_AUTHENTICATION_ENABLED));
    boolean shiroEnabled = TRUE.equalsIgnoreCase(providerParams.get(SHIRO_AUTHENTICATION_ENABLED));

    if(shiroEnabled || ldapEnabled || useKerberos) {
      SSHConfiguration configuration = new SSHConfiguration();

      // ssh port not optional
      configuration.setPort(Integer.parseInt(providerParams.get(SSH_PORT)));
      // ssh fingerprint -> has default
      String sshLocation = providerParams.get(SSH_FINGERPRINT_LOCATION);
      if (sshLocation == null) {
        sshLocation = "/var/run/knox/ssh.fingerprint";
      }
      configuration.setSshFingerprintLocation(sshLocation);

      // use kerberos -> default is false
      configuration.setUseKerberosAuth(useKerberos);
      if (useKerberos) {
        // keytab location -> has default
        String keytabLocation = providerParams.get(KEYTAB_LOCATION);
        if (keytabLocation == null) {
          keytabLocation = "/etc/knox/conf/knox.service.keytab";
        }
        configuration.setKeytabLocation(keytabLocation);
        // principal -> not optional if kerberos is on
        configuration.setServicePrincipal(providerParams.get(PROVIDER_PRINCIPAL));
      }

      // workers -> optional
      String workersString = providerParams.get(WORKERS);
      int workers;
      if (workersString != null) {
        workers = Integer.parseInt(workersString);
      } else {
        workers = -1;
      }
      configuration.setWorkers(workers);

      // ldap authorization base DN -> no default
      configuration.setUseLdapAuth(ldapEnabled);
      if(ldapEnabled) {
        configuration.setAuthorizationBase(
            providerParams.get(LDAP_AUTHORIZATION_BASE_DN));
        configuration.setAuthorizationUser(
            providerParams.get(LDAP_AUTHORIZATION_USER));
        configuration.setAuthorizationPass(
            providerParams.get(LDAP_AUTHORIZATION_PASSWORD));
        configuration.setAuthorizationGroupAttribute(providerParams.get(LDAP_AUTHORIZATION_ATTRIBUTE));
        configuration.setAuthorizationURL(
            providerParams.get(LDAP_AUTHORIZATION_URL));
        configuration.setAuthorizationNameAttribute(
            providerParams.get(LDAP_AUTHORIZATION_NAME_ATTRIBUTE));
        String authorizationGroupIdsStr = providerParams.get(LDAP_AUTHORIZATION_GROUP_IDS);
        if(authorizationGroupIdsStr != null) {
          configuration
              .setAuthorizationGroupIds(authorizationGroupIdsStr.split(";"));
        }
        configuration.setAuthenticationURL(
            providerParams.get(LDAP_AUTHENTICATION_URL));
        configuration.setAuthenticationPattern(
            providerParams.get(LDAP_AUTHENTICATION_NAME_PATTERN));
      }

      String knoxKeyfile = providerParams.get(TUNNEL_KEYFILE);
      if(knoxKeyfile == null){
        knoxKeyfile = "/etc/knox/conf/id_knox.pem";
      }
      configuration.setKnoxKeyfile(knoxKeyfile);

      String knoxLoginUser = providerParams.get(TUNNEL_USER );
      if(knoxLoginUser == null){
        knoxLoginUser = "knox";
      }
      configuration.setKnoxLoginUser(knoxLoginUser);

      String loginCommand = providerParams.get(LOGIN_COMMAND);
      if(loginCommand == null){
        loginCommand = "exec sudo -iu {0}; logout\n";
      }
      configuration.setLoginCommand(loginCommand);

      String tunnelTimeoutStr = providerParams.get(TUNNEL_TIMEOUT);
      if(tunnelTimeoutStr == null) {
        tunnelTimeoutStr = "1000"; //default 1 sec
      }
      configuration.setTunnelConnectTimeout(Integer.parseInt(tunnelTimeoutStr));

      String streamFlushPeriodStr = providerParams.get(STREAM_FLUSH_PERIOD);
      long streamFlushPeriod = DEFAULT_STREAM_FLUSH_PERIOD;
      if(streamFlushPeriodStr != null) {
        streamFlushPeriod = Long.parseLong(streamFlushPeriodStr);
      }
      configuration.setStreamFlusherPeriod(streamFlushPeriod);

      configuration.setUseShiroAuth(shiroEnabled);

      if(providerParams.containsKey(SESSION_IDLE_TIMEOUT)) {
        configuration.setSessionIdleTimeout(Long.parseLong(providerParams.get(SESSION_IDLE_TIMEOUT)));
      }

      return configuration;
    } else {
      throw new IllegalArgumentException("Configuration does not include any authentication mechanisms");
    }
  }
}
