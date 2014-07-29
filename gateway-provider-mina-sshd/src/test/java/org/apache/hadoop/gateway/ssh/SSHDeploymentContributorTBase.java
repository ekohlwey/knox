package org.apache.hadoop.gateway.ssh;

import static junit.framework.Assert.assertNull;
import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.hadoop.gateway.deploy.DeploymentContext;
import org.apache.hadoop.gateway.topology.Param;
import org.apache.hadoop.gateway.topology.Provider;
import org.apache.hadoop.gateway.topology.Topology;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.SshServer;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.UserAuthPassword;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.auth.UserAuthPublicKey;
import org.apache.sshd.server.session.ServerSession;
import org.bouncycastle.openssl.PEMWriter;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RunWith(FrameworkRunner.class)
/**
 * SSH Deployment Contributor Test
 * 
 * Setting up LDAP, KDC, SSH Provider, and client to test the "help" command
 */
public class SSHDeploymentContributorTBase extends AbstractLdapTestUnit {
  public static class PipingCommandFactory implements Factory<Command> {

    private final PipedOutputStream outPipe;

    public PipingCommandFactory(PipedInputStream inPipe) {
      outPipe = new PipedOutputStream();
      try {
        outPipe.connect(inPipe);
      } catch (IOException e) {
        LOG.error("Can't close pipe", e);
      }
    }

    @Override
    public Command create() {
      return new Command() {

        private InputStream inputStream;
        private OutputStream out;
        private OutputStream err;
        private ExitCallback callback;

        @Override
        public void start(Environment env) throws IOException {
          new Thread() {
            @Override
            public void run() {
              while(true) {
                byte[] buffer = new byte[1024];
                int read;
                try {
                  while ((read = inputStream.read(buffer)) > 0) {
                    outPipe.write(buffer, 0, read);
                    outPipe.flush();
                  }
                } catch (IOException e) {
                  LOG.error("Cant write to pipe", e);
                } finally {
                  try {
                    outPipe.close();
                  } catch (IOException e) {
                    LOG.error("Cant close pipe", e);
                  }
                  callback.onExit(0);
                }
              }
            }
          }.start();
          try {
            out.write("connected out\n".getBytes());
            out.flush();
          } catch (IOException e) {
            LOG.error("Unable to write out connection message.", e);
          }
          try {
            err.write("connected error\n".getBytes());
            err.flush();
          } catch (IOException e) {
            LOG.error("Unable to write error connection message.", e);
          }
        }

        @Override
        public void setOutputStream(OutputStream out) {
          this.out = out;
        }

        @Override
        public void setInputStream(final InputStream in) {
          this.inputStream = in;
        }

        @Override
        public void setExitCallback(ExitCallback callback) {
          this.callback = callback;
        }

        @Override
        public void setErrorStream(OutputStream err) {
          this.err = err;
        }

        @Override
        public void destroy() {

        }
      };
    }
  }

  private static final Logger LOG = LoggerFactory
      .getLogger(SSHDeploymentContributorITest.class);

  @Rule
  public TemporaryFolder tempFolder = new TemporaryFolder();

  protected class TestProvider extends Provider {

    protected TestProvider() {
      super();

      addParam(buildParam("main.ldapRealm",
          "org.apache.hadoop.gateway.shirorealm.KnoxLdapRealm"));
      addParam(buildParam("main.ldapGroupContextFactory",
          "org.apache.hadoop.gateway.shirorealm.KnoxLdapContextFactory"));
      addParam(buildParam("main.ldapRealm.userDnTemplate",
          "uid={0},dc=example,dc=com"));
      addParam(buildParam("main.ldapRealm.authorizationEnabled", "true"));
      addParam(buildParam("main.ldapRealm.contextFactory.url",
          "ldap://localhost:60389"));
      addParam(
          buildParam("main.ldapRealm.contextFactory.authenticationMechanism",
              "simple"));
      addParam(buildParam("main.ldapRealm.contextFactory.systemUsername",
          "uid=client,dc=example,dc=com"));
      addParam(
          buildParam("main.ldapRealm.contextFactory.systemPassword", "secret"));
    }

  }

  protected class TestProviderConfigurer extends ProviderConfigurer {

    private final SSHConfiguration sshConfiguration;

    protected TestProviderConfigurer(SSHConfiguration sshConfiguration) {
      this.sshConfiguration = sshConfiguration;
    }

    @Override
    public SSHConfiguration configure(Provider provider) {
      return sshConfiguration;
    }
  }

  private static class TestShiroProviderConfigurer extends ProviderConfigurer {

    private final SSHConfiguration sshConfiguration;

    public TestShiroProviderConfigurer(SSHConfiguration sshConfiguration) {
      this.sshConfiguration = sshConfiguration;
    }

    @Override
    public SSHConfiguration configure(Provider provider) {
      return sshConfiguration;

    }
  }

  protected static class UserAuthStaticPassword extends UserAuthPassword {

    protected static class Factory extends UserAuthPassword.Factory {

      @Override
      public UserAuth create() {
        return new UserAuthStaticPassword();
      }
    }

    @Override
    public void init(ClientSession session, String service,
        List<Object> identities) throws Exception {
      super.init(session, service, Arrays.<Object> asList("secret"));
    }
  }

  private static Param buildParam(String name, String value) {
    Param param = new Param();
    param.setName(name);
    param.setValue(value);
    return param;
  }


}
