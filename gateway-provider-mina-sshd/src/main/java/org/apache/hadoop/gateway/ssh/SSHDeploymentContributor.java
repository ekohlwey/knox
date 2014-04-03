package org.apache.hadoop.gateway.ssh;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.hadoop.gateway.deploy.DeploymentContext;
import org.apache.hadoop.gateway.deploy.ProviderDeploymentContributorBase;
import org.apache.hadoop.gateway.descriptor.FilterParamDescriptor;
import org.apache.hadoop.gateway.descriptor.ResourceDescriptor;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Service;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.gss.GSSAuthenticator;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

public class SSHDeploymentContributor extends ProviderDeploymentContributorBase {

  private final Thread shutdownHandler = new Thread() {
    public void run() {
      if (sshd != null) {
        try {
          sshd.stop(true);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
    };
  };

  private SshServer sshd;

  private ProviderConfigurer configurer;

  @Override
  public String getRole() {
    return "ssh";
  }

  @Override
  public String getName() {
    return "SshProvider";
  }

  @Override
  public void contributeFilter(DeploymentContext context, Provider provider,
      Service service, ResourceDescriptor resource,
      List<FilterParamDescriptor> params) {
    // noop
  }

  public SSHDeploymentContributor() {
    this(new StandardProviderConfigurer());
  }

  public SSHDeploymentContributor(ProviderConfigurer configurer) {
    this.configurer = configurer;
  }

  @Override
  public void contributeProvider(DeploymentContext context, Provider provider)
      throws SSHServerException {
    SSHConfiguration configuration = configurer.configure(provider);

    sshd = SshServer.setUpDefaultServer();
    sshd.setPort(configuration.getPort());
    sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(configuration
        .getSshFingerprintLocation()));
    List<NamedFactory<UserAuth>> userAuthFactories = new ArrayList<NamedFactory<UserAuth>>(
        1);
    userAuthFactories.add(new KnoxUserAuthGSS.Factory());
    sshd.setUserAuthFactories(userAuthFactories);

    GSSAuthenticator authenticator = new GSSAuthenticator();
    authenticator.setKeytabFile(configuration.getKeytabLocation());
    String servicePrincipal = configuration.getServicePrincipal();
    if (servicePrincipal != null) {
      authenticator.setServicePrincipalName(servicePrincipal);
    }
    sshd.setGSSAuthenticator(authenticator);
    int workers = configuration.getWorkers();
    if (workers > 0) {
      sshd.setNioWorkers(workers);
    }
    sshd.setShellFactory(new KnoxTunnelShellFactory(provider.getTopology()
        .getName()));
    try {
      sshd.start();
    } catch (IOException e) {
      throw new SSHServerException(e);
    } finally {
      Runtime.getRuntime().addShutdownHook(shutdownHandler);
    }
  }

}
