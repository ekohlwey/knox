package org.apache.hadoop.gateway.ssh;

import java.util.Arrays;

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
  private boolean useLdapAuth = false;
  private boolean useKerberosAuth = false;
  private boolean useShiroAuth = true;
  private String knoxKeyfile;
  private String knoxLoginUser;
  private String loginCommand;
  private long tunnelConnectTimeout;
  private int queueSize = ProviderConfigurer.DEFAULT_QUEUE_SIZE;
  private long streamFlusherPeriod = ProviderConfigurer.DEFAULT_STREAM_FLUSH_PERIOD;
  private long sessionIdleTimeout = 60 * 60 * 1000l; //default 1 hr;

  public SSHConfiguration() {
  }
  
  public String getKnoxLoginUser() {
    return knoxLoginUser;
  }
  
  public void setKnoxLoginUser(String knoxLoginUser) {
    this.knoxLoginUser = knoxLoginUser;
  }
  

  public void setPort(int port) {
    this.port = port;
  }

  public void setSshFingerprintLocation(String sshFingerprintLocation) {
    this.sshFingerprintLocation = sshFingerprintLocation;
  }

  public void setKeytabLocation(String keytabLocation) {
    this.keytabLocation = keytabLocation;
  }

  public void setServicePrincipal(String servicePrincipal) {
    this.servicePrincipal = servicePrincipal;
  }

  public void setWorkers(int workers) {
    this.workers = workers;
  }

  public void setAuthorizationBase(String authorizationBase) {
    this.authorizationBase = authorizationBase;
  }

  public void setAuthorizationUser(String authorizationUser) {
    this.authorizationUser = authorizationUser;
  }

  public void setAuthorizationPass(String authorizationPass) {
    this.authorizationPass = authorizationPass;
  }

  public void setAuthorizationGroupAttribute(String authorizationGroupAttribute) {
    this.authorizationGroupAttribute = authorizationGroupAttribute;
  }

  public void setAuthorizationURL(String authorizationURL) {
    this.authorizationURL = authorizationURL;
  }

  public void setAuthorizationNameAttribute(String authorizationNameAttribute) {
    this.authorizationNameAttribute = authorizationNameAttribute;
  }

  public void setAuthenticationURL(String authenticationURL) {
    this.authenticationURL = authenticationURL;
  }

  public void setAuthorizationGroupIds(String[] authorizationGroupIds) {
    this.authorizationGroupIds = authorizationGroupIds;
  }

  public void setAuthenticationPattern(String authenticationPattern) {
    this.authenticationPattern = authenticationPattern;
  }

  public void setUseLdapAuth(boolean useLdapAuth) {
    this.useLdapAuth = useLdapAuth;
  }

  public void setUseKerberosAuth(boolean useKerberosAuth) {
    this.useKerberosAuth = useKerberosAuth;
  }

  public void setKnoxKeyfile(String knoxKeyfile) {
    this.knoxKeyfile = knoxKeyfile;
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

  public String getKnoxKeyfile() {
    return knoxKeyfile;
  }

  public String getLoginCommand() {
    return loginCommand;
  }
  
  public void setLoginCommand(String loginCommand) {
    this.loginCommand = loginCommand;
  }
  
  public void setTunnelConnectTimeout(long tunnelConnectTimeout) {
    this.tunnelConnectTimeout = tunnelConnectTimeout;
  }
  
  public long getTunnelConnectTimeout() {
    return tunnelConnectTimeout;
  }

  public int getQueueSize() {
    return queueSize;
  }

  public void setQueueSize(int queueSize) {
    this.queueSize = queueSize;
  }

  public boolean isUseShiroAuth() {
    return useShiroAuth;
  }

  public void setUseShiroAuth(boolean useShiroAuth) {
    this.useShiroAuth = useShiroAuth;
  }

  public long getStreamFlusherPeriod() {
    return streamFlusherPeriod;
  }

  public void setStreamFlusherPeriod(long streamFlusherPeriod) {
    this.streamFlusherPeriod = streamFlusherPeriod;
  }

  public long getSessionIdleTimeout() {
    return sessionIdleTimeout;
  }

  public void setSessionIdleTimeout(long sessionIdleTimeout) {
    this.sessionIdleTimeout = sessionIdleTimeout;
  }

  @Override
  public String toString() {
    return "SSHConfiguration{" +
        "port=" + port +
        ", sshFingerprintLocation='" + sshFingerprintLocation + '\'' +
        ", keytabLocation='" + keytabLocation + '\'' +
        ", servicePrincipal='" + servicePrincipal + '\'' +
        ", workers=" + workers +
        ", authorizationBase='" + authorizationBase + '\'' +
        ", authorizationUser='" + authorizationUser + '\'' +
        ", authorizationPass='" + authorizationPass + '\'' +
        ", authorizationGroupAttribute='" + authorizationGroupAttribute + '\'' +
        ", authorizationURL='" + authorizationURL + '\'' +
        ", authorizationNameAttribute='" + authorizationNameAttribute + '\'' +
        ", authenticationURL='" + authenticationURL + '\'' +
        ", authorizationGroupIds=" +
        Arrays.toString(authorizationGroupIds) +
        ", authenticationPattern='" + authenticationPattern + '\'' +
        ", useLdapAuth=" + useLdapAuth +
        ", useKerberosAuth=" + useKerberosAuth +
        ", useShiroAuth=" + useShiroAuth +
        ", knoxKeyfile='" + knoxKeyfile + '\'' +
        ", knoxLoginUser='" + knoxLoginUser + '\'' +
        ", loginCommand='" + loginCommand + '\'' +
        ", tunnelConnectTimeout=" + tunnelConnectTimeout +
        ", queueSize=" + queueSize +
        ", streamFlusherPeriod=" + streamFlusherPeriod +
        '}';
  }
}
