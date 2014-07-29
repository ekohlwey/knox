package org.apache.hadoop.gateway.ssh;

import static java.lang.Integer.parseInt;

import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.PosixParser;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.hadoop.gateway.config.GatewayConfig;
import org.apache.hadoop.gateway.deploy.DeploymentContext;
import org.apache.hadoop.gateway.descriptor.FilterParamDescriptor;
import org.apache.hadoop.gateway.descriptor.GatewayDescriptor;
import org.apache.hadoop.gateway.descriptor.ResourceDescriptor;
import org.apache.hadoop.gateway.topology.Service;
import org.apache.hadoop.gateway.topology.Topology;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.descriptor.api.webapp30.WebAppDescriptor;
import org.junit.Test;
import org.junit.runner.JUnitCore;
import org.junit.runner.RunWith;

@RunWith(FrameworkRunner.class)
@CreateDS(name = "KnoxLDAPPasswordAuthenticatorITest-class", enableChangeLog = false, partitions = { @CreatePartition(name = "example", suffix = "dc=example,dc=com", contextEntry = @ContextEntry(entryLdif = "dn: dc=example,dc=com\n"
    + "objectClass: domain\n" + "dc: example")) })
@CreateLdapServer(transports = { @CreateTransport(address = "localhost", protocol = "LDAP", port = 60389) })
@ApplyLdifs({
    // client
    "dn: uid=client,dc=example,dc=com", "objectClass: top",
    "objectClass: person", "objectClass: inetOrgPerson", "cn: client",
    "sn: client", "uid: client", "ou: someOU", "userPassword: secret" })
public class SSHDeploymentContributorRunUtility extends
    SSHDeploymentContributorTBase {

  private static SSHConfiguration configuration = new SSHConfiguration();

  private static class TestDeploymentContext implements DeploymentContext {

    final Topology topology;

    public TestDeploymentContext(String name) {
      this.topology = new Topology();
      topology.setName(name);
    }

    @Override
    public WebArchive getWebArchive() {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public WebAppDescriptor getWebAppDescriptor() {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public Topology getTopology() {
      return topology;
    }

    @Override
    public GatewayDescriptor getGatewayDescriptor() {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public GatewayConfig getGatewayConfig() {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public <T> T getDescriptor(String name) {
      // TODO Auto-generated method stub
      return null;
    }

    @Override
    public void contributeFilter(Service service, ResourceDescriptor resource,
        String role, String name, List<FilterParamDescriptor> params) {
      // TODO Auto-generated method stub

    }

    @Override
    public void addDescriptor(String name, Object descriptor) {
      // TODO Auto-generated method stub

    }
  };

  public static void main(String[] args) throws Throwable {

    Options options = new Options();
    options.addOption("sp", true, "The ssh port.");
    options.addOption("tt", true, "The tunnel timeout.");
    options.addOption("lu", true, "The login user for the remote host.");
    options.addOption("pk", true,
        "The private key file to connect to the remote host.");
    options.addOption("lc", true,
        "The command to run when logging into the knox host.");

    PosixParser parser = new PosixParser();
    CommandLine line = parser.parse(options, args);
    int port = line.hasOption("sp") ? parseInt(line.getOptionValue("sp"))
        : 60022;
    int timeout = line.hasOption("tt") ? parseInt(line.getOptionValue("tt"))
        : 1000;
    String loginUser = line.hasOption("lu") ? line.getOptionValue("lu")
        : "knox";
    String keyLocation = line.hasOption("pk") ? line.getOptionValue("pk")
        : System.getProperty("user.home") + "/knox-pk.pem";
    String command = line.hasOption("lc") ? line.getOptionValue("lc") : "";

    configuration.setPort(port);
    configuration.setUseShiroAuth(true);
    configuration.setTunnelConnectTimeout(timeout);
    configuration.setKnoxLoginUser(loginUser);
    configuration.setKnoxKeyfile(keyLocation);
    configuration.setLoginCommand(command);

    JUnitCore junit = new JUnitCore();
    junit.run(SSHDeploymentContributorRunUtility.class);
  }

  @Test
  public void runContributor() {
    TestProvider provider = new TestProvider();
    SSHDeploymentContributor contributor = new SSHDeploymentContributor(
        new TestProviderConfigurer(configuration));
    DeploymentContext context = new TestDeploymentContext("test");
    contributor.contributeProvider(context, provider);
    while (true) {
      try {
        Thread.sleep(1000);
      } catch (InterruptedException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }
    }
  }

}
