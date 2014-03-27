package org.apache.hadoop.gateway.ssh;

public class SSHConfiguration {

  private int port;
  private String sshFingerprintLocation;
  private String keytabLocation;
  private String servicePrincipal;
  private int workers;

  public SSHConfiguration(int port, String sshFingerprintLocation, String keytabLocation,
      String servicePrincipal, int workers) {
    this.port = port;
    this.sshFingerprintLocation = sshFingerprintLocation;
    this.keytabLocation = keytabLocation;
    this.servicePrincipal = servicePrincipal;
    this.workers = workers;
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

}
