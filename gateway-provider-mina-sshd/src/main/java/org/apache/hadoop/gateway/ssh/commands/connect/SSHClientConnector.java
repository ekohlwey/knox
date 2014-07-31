package org.apache.hadoop.gateway.ssh.commands.connect;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.hadoop.gateway.ssh.commands.connect.SSHConnector.SshClientConnectTimeoutException;
import org.apache.hadoop.gateway.ssh.commands.connect.SSHConnector.SshClientConnectionFailedException;
import org.apache.hadoop.gateway.ssh.commands.connect.SSHConnector.SshClientConnectionUnauthorizedException;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.SshException;

public class SSHClientConnector {

  private final SSHConfiguration sshConfiguration;

  public SSHClientConnector(SSHConfiguration sshConfiguration) {
    this.sshConfiguration = sshConfiguration;
  }

  public ClientSession connect(SshClient sshClient, String host, Integer port)
      throws IOException, InterruptedException,
      SshClientConnectTimeoutException, SshClientConnectionFailedException,
      SshClientConnectionUnauthorizedException {
    try{
      InetAddress.getByName(host);
    } catch(UnknownHostException e){
      throw new SshClientConnectionFailedException(e);
    }
    ConnectFuture connectFuture = sshClient.connect(
        sshConfiguration.getKnoxLoginUser(), host, port);
    if (!connectFuture.await(sshConfiguration.getTunnelConnectTimeout())) {
      throw new SshClientConnectTimeoutException(connectFuture.getException());
    }
    if (!connectFuture.isConnected()) {
      throw new SshClientConnectionFailedException(
          connectFuture.getException());
    }
    ClientSession session = connectFuture.getSession();
    AuthFuture auth = session.auth();
    if (!auth.await(sshConfiguration.getTunnelConnectTimeout())) {
      throw new SshClientConnectTimeoutException(auth.getException());
    }
    try {
      auth.verify();
    } catch (SshException e) {
      throw new SshClientConnectionUnauthorizedException(e.getMessage(), e);
    }
    return session;
  }
}