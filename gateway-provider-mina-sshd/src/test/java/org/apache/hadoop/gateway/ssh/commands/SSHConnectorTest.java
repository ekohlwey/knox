package org.apache.hadoop.gateway.ssh.commands;

import static org.apache.hadoop.gateway.ssh.commands.SSHConnector.SshClientConnector;

import java.io.IOException;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.common.SshException;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;

public class SSHConnectorTest {

  @Test(expected = SSHConnector.SshClientConnectTimeoutException.class)
  public void testSshClientConnectorConnectTimeoutException() throws Exception {
    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    String user = "user";
    String host = "host";
    Integer port = 22;

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port)).andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(false);
    EasyMock.expect(connectFutureMock.getException()).andReturn(new IOException());
    EasyMock.replay(sshClientMock, connectFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration, user);
    sshClientConnector.connect(sshClientMock, host, port);

    EasyMock.verify(sshClientMock, connectFutureMock);
  }

  @Test(expected = SSHConnector.SshClientConnectionFailedException.class)
  public void testSshClientConnectorConnectFailedException() throws Exception {
    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    String user = "user";
    String host = "host";
    Integer port = 22;

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port)).andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(true);
    EasyMock.expect(connectFutureMock.isConnected()).andReturn(false);
    EasyMock.expect(connectFutureMock.getException()).andReturn(new IOException());
    EasyMock.replay(sshClientMock, connectFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration, user);
    sshClientConnector.connect(sshClientMock, host, port);

    EasyMock.verify(sshClientMock, connectFutureMock);
  }

  @Test(expected = SSHConnector.SshClientConnectTimeoutException.class)
  public void testSshClientConnectorAuthTimeoutException() throws Exception {
    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    String user = "user";
    String host = "host";
    Integer port = 22;

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    ClientSession clientSessionMock = EasyMock.createMock(ClientSession.class);
    AuthFuture authFutureMock = EasyMock.createMock(AuthFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port)).andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(true);
    EasyMock.expect(connectFutureMock.isConnected()).andReturn(true);
    EasyMock.expect(connectFutureMock.getSession()).andReturn(clientSessionMock);
    EasyMock.expect(clientSessionMock.auth()).andReturn(authFutureMock);
    EasyMock.expect(authFutureMock.await(0)).andReturn(false);
    EasyMock.expect(authFutureMock.getException()).andReturn(new IOException());
    EasyMock.replay(sshClientMock, connectFutureMock, clientSessionMock, authFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration, user);
    sshClientConnector.connect(sshClientMock, host, port);

    EasyMock.verify(sshClientMock, connectFutureMock, clientSessionMock, authFutureMock);
  }

  @Test(expected = SSHConnector.SshClientConnectionUnauthorizedException.class)
  public void testSshClientConnectorAuthUnauthorizedException() throws Exception {
    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    String user = "user";
    String host = "host";
    Integer port = 22;

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    ClientSession clientSessionMock = EasyMock.createMock(ClientSession.class);
    AuthFuture authFutureMock = EasyMock.createMock(AuthFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port)).andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(true);
    EasyMock.expect(connectFutureMock.isConnected()).andReturn(true);
    EasyMock.expect(connectFutureMock.getSession()).andReturn(clientSessionMock);
    EasyMock.expect(clientSessionMock.auth()).andReturn(authFutureMock);
    EasyMock.expect(authFutureMock.await(0)).andReturn(true);
    authFutureMock.verify();
    EasyMock.expectLastCall().andThrow(new SshException());
    EasyMock.replay(sshClientMock, connectFutureMock, clientSessionMock, authFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration, user);
    sshClientConnector.connect(sshClientMock, host, port);

    EasyMock.verify(sshClientMock, connectFutureMock, clientSessionMock, authFutureMock);
  }

  @Test
  public void testSshClientConnector() throws Exception {
    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    String user = "user";
    String host = "host";
    Integer port = 22;

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    ClientSession clientSessionMock = EasyMock.createMock(ClientSession.class);
    AuthFuture authFutureMock = EasyMock.createMock(AuthFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port)).andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(true);
    EasyMock.expect(connectFutureMock.isConnected()).andReturn(true);
    EasyMock.expect(connectFutureMock.getSession()).andReturn(clientSessionMock);
    EasyMock.expect(clientSessionMock.auth()).andReturn(authFutureMock);
    EasyMock.expect(authFutureMock.await(0)).andReturn(true);
    authFutureMock.verify();
    EasyMock.expectLastCall();
    EasyMock.replay(sshClientMock, connectFutureMock, clientSessionMock, authFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration, user);
    ClientSession clientSession =
        sshClientConnector.connect(sshClientMock, host, port);

    Assert.assertEquals(clientSessionMock, clientSession);

    EasyMock.verify(sshClientMock, connectFutureMock, clientSessionMock, authFutureMock);
  }
}
