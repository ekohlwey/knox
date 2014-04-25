package org.apache.hadoop.gateway.ssh;

public class SSHConfiguration {

  private int port;
  private String sshFingerprintLocation;
  private String keytabLocation;
  private String servicePrincipal;
  private int workers;
  private String authorizationBase;
  private String authorizationUser;
  private String authorizationPass;
  private String authorizationGroupAttribute;
  private String authorizationURL;
  private String authorizationNameAttribute;
  private String authenticationURL;
  private String[] authorizationGroupIds;
  private String authenticationPattern;
  private boolean useLdapAuth;
  private boolean useKerberosAuth;

  public SSHConfiguration(int port, String sshFingerprintLocation,
      boolean useKerberos, String keytabLocation, String servicePrincipal,
      int workers, String authorizationBase, String authorizationUser,
      String authorizationPass, String authorizationGroupAttribute,
      String authorizationURL, String authorizationNameAttribute,
      String authenticationURL, String authenticationPattern,
      String[] authorizationGroupIds, boolean useLdapAuth) {
    this.port = port;
    this.sshFingerprintLocation = sshFingerprintLocation;
    this.keytabLocation = keytabLocation;
    this.servicePrincipal = servicePrincipal;
    this.workers = workers;
    this.authorizationBase = authorizationBase;
    this.authorizationUser = authorizationUser;
    this.authorizationPass = authorizationPass;
    this.authorizationGroupAttribute = authorizationGroupAttribute;
    this.authorizationURL = authorizationURL;
    this.authorizationNameAttribute = authorizationNameAttribute;
    this.authenticationURL = authenticationURL;
    this.authorizationGroupIds = authorizationGroupIds;
    this.authenticationPattern = authenticationPattern;
    this.useKerberosAuth = useKerberos;
    this.useLdapAuth = useLdapAuth;
  }

  public String getAuthenticationPattern() {
    return authenticationPattern;
  }

  public String[] getAuthorizationGroupIds() {
    return authorizationGroupIds;
  }

  public String getAuthenticationURL() {
    return authenticationURL;
  }

  public String getAuthorizationBase() {
    return authorizationBase;
  }

  public String getAuthorizationGroupAttribute() {
    return authorizationGroupAttribute;
  }

  public String getAuthorizationNameAttribute() {
    return authorizationNameAttribute;
  }

  public String getAuthorizationPass() {
    return authorizationPass;
  }

  public String getAuthorizationURL() {
    return authorizationURL;
  }

  public String getAuthorizationUser() {
    return authorizationUser;
  }

  public int getPort() {
    return port;
  }

  public String getSshFingerprintLocation() {
    return sshFingerprintLocation;
  }

  public String getKeytabLocation() {
    return keytabLocation;
  }

  public String getServicePrincipal() {
    return servicePrincipal;
  }

  public int getWorkers() {
    return workers;
  }

  public boolean isUseKerberosAuth() {
    return useKerberosAuth;
  }

  public boolean isUseLdapAuth() {
    return useLdapAuth;
  }

}
