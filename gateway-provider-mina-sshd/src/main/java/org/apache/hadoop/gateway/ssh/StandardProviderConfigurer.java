package org.apache.hadoop.gateway.ssh;

import java.util.Map;

import org.apache.hadoop.gateway.topology.Provider;

public class StandardProviderConfigurer implements ProviderConfigurer {

  @Override
  public SSHConfiguration configure(Provider provider) {
    Map<String, String> providerParams = provider.getParams();
    int port = Integer.parseInt(providerParams.get(SSH_PORT));
    String sshLocation = providerParams.get(SSH_FINGERPRINT_LOCATION);
    if (sshLocation == null) {
      sshLocation = "/var/run/knox/ssh.fingerprint";
    }
    String keytabLocation = providerParams.get(KEYTAB_LOCATION);
    if (keytabLocation == null) {
      keytabLocation = "/etc/knox/conf/knox.service.keytab";
    }
    String servicePrincipal = providerParams.get(PROVIDER_PRINCIPAL);
    String workersString = providerParams.get(WORKERS);
    int workers;
    if (workersString != null) {
      workers = Integer.parseInt(workersString);
    } else {
      workers = -1;
    }
    return new SSHConfiguration(port, sshLocation, keytabLocation, servicePrincipal, workers);
  }

}
