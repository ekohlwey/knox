package org.apache.hadoop.gateway.ssh.commands.connect;

import java.util.Arrays;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.UserAuth;
import org.apache.sshd.client.auth.UserAuthPublicKey;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;

public class SSHClientBuilder {

  private final SSHConfiguration sshConfiguration;

  public SSHClientBuilder(SSHConfiguration sshConfiguration) {
    this.sshConfiguration = sshConfiguration;
  }

  public SshClient buildAndStartClient() {
    SshClient client = SshClient.setUpDefaultClient();
    client.setKeyPairProvider(new FileKeyPairProvider(
        new String[] { sshConfiguration.getKnoxKeyfile() }));
    client.setUserAuthFactories(Arrays
        .<NamedFactory<UserAuth>> asList(new UserAuthPublicKey.Factory()));
    client.start();
    return client;
  }
}