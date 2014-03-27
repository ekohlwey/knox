package org.apache.hadoop.gateway.ssh;

import org.apache.hadoop.gateway.topology.Provider;

public interface ProviderConfigurer {
  

  public static final String SSH_PORT = "port";
  public static final String SSH_FINGERPRINT_LOCATION = "ssh-fingerprint-location";
  public static final String KEYTAB_LOCATION = "keytab";
  public static final String PROVIDER_PRINCIPAL = "kerberos-principal";
  public static final String WORKERS = "workers";

  
  public SSHConfiguration configure(Provider provider );
}
