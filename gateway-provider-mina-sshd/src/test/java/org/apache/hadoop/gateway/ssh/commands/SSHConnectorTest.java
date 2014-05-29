package org.apache.hadoop.gateway.ssh.commands;

import static org.apache.hadoop.gateway.ssh.commands.SSHConnector.SshClientConnector;
import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.hadoop.gateway.ssh.SSHConfiguration;
import org.apache.sshd.ClientChannel;
import org.apache.sshd.ClientSession;
import org.apache.sshd.SshClient;
import org.apache.sshd.client.channel.ChannelShell;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.future.OpenFuture;
import org.apache.sshd.common.PtyMode;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.future.CloseFuture;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;

import com.google.common.io.ByteStreams;
import com.google.common.io.CharStreams;

public class SSHConnectorTest {

  @Test(expected = SSHConnector.SshClientConnectTimeoutException.class)
  public void testSshClientConnectorConnectTimeoutException() throws Exception {
    String user = "user";
    String host = "host";
    Integer port = 22;

    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    sshConfiguration.setKnoxLoginUser(user);

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port))
        .andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(false);
    EasyMock.expect(connectFutureMock.getException())
        .andReturn(new IOException());
    EasyMock.replay(sshClientMock, connectFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration);
    sshClientConnector.connect(sshClientMock, host, port);

    EasyMock.verify(sshClientMock, connectFutureMock);
  }

  @Test(expected = SSHConnector.SshClientConnectionFailedException.class)
  public void testSshClientConnectorConnectFailedException() throws Exception {
    String user = "user";
    String host = "host";
    Integer port = 22;

    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    sshConfiguration.setKnoxLoginUser(user);

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port))
        .andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(true);
    EasyMock.expect(connectFutureMock.isConnected()).andReturn(false);
    EasyMock.expect(connectFutureMock.getException())
        .andReturn(new IOException());
    EasyMock.replay(sshClientMock, connectFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration);
    sshClientConnector.connect(sshClientMock, host, port);

    EasyMock.verify(sshClientMock, connectFutureMock);
  }

  @Test(expected = SSHConnector.SshClientConnectTimeoutException.class)
  public void testSshClientConnectorAuthTimeoutException() throws Exception {
    String user = "user";
    String host = "host";
    Integer port = 22;

    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    sshConfiguration.setKnoxLoginUser(user);

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    ClientSession clientSessionMock = EasyMock.createMock(ClientSession.class);
    AuthFuture authFutureMock = EasyMock.createMock(AuthFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port))
        .andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(true);
    EasyMock.expect(connectFutureMock.isConnected()).andReturn(true);
    EasyMock.expect(connectFutureMock.getSession())
        .andReturn(clientSessionMock);
    EasyMock.expect(clientSessionMock.auth()).andReturn(authFutureMock);
    EasyMock.expect(authFutureMock.await(0)).andReturn(false);
    EasyMock.expect(authFutureMock.getException()).andReturn(new IOException());
    EasyMock.replay(sshClientMock, connectFutureMock, clientSessionMock,
        authFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration);
    sshClientConnector.connect(sshClientMock, host, port);

    EasyMock.verify(sshClientMock, connectFutureMock, clientSessionMock,
        authFutureMock);
  }

  @Test(expected = SSHConnector.SshClientConnectionUnauthorizedException.class)
  public void testSshClientConnectorAuthUnauthorizedException()
      throws Exception {
    String user = "user";
    String host = "host";
    Integer port = 22;

    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    sshConfiguration.setKnoxLoginUser(user);

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    ClientSession clientSessionMock = EasyMock.createMock(ClientSession.class);
    AuthFuture authFutureMock = EasyMock.createMock(AuthFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port))
        .andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(true);
    EasyMock.expect(connectFutureMock.isConnected()).andReturn(true);
    EasyMock.expect(connectFutureMock.getSession())
        .andReturn(clientSessionMock);
    EasyMock.expect(clientSessionMock.auth()).andReturn(authFutureMock);
    EasyMock.expect(authFutureMock.await(0)).andReturn(true);
    authFutureMock.verify();
    EasyMock.expectLastCall().andThrow(new SshException());
    EasyMock.replay(sshClientMock, connectFutureMock, clientSessionMock,
        authFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration);
    sshClientConnector.connect(sshClientMock, host, port);

    EasyMock.verify(sshClientMock, connectFutureMock, clientSessionMock,
        authFutureMock);
  }

  @Test
  public void testSshClientConnector() throws Exception {
    String user = "user";
    String host = "host";
    Integer port = 22;

    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    sshConfiguration.setKnoxLoginUser(user);

    SshClient sshClientMock = EasyMock.createMock(SshClient.class);
    ConnectFuture connectFutureMock = EasyMock.createMock(ConnectFuture.class);
    ClientSession clientSessionMock = EasyMock.createMock(ClientSession.class);
    AuthFuture authFutureMock = EasyMock.createMock(AuthFuture.class);
    EasyMock.expect(sshClientMock.connect(user, host, port))
        .andReturn(connectFutureMock);
    EasyMock.expect(connectFutureMock.await(0)).andReturn(true);
    EasyMock.expect(connectFutureMock.isConnected()).andReturn(true);
    EasyMock.expect(connectFutureMock.getSession())
        .andReturn(clientSessionMock);
    EasyMock.expect(clientSessionMock.auth()).andReturn(authFutureMock);
    EasyMock.expect(authFutureMock.await(0)).andReturn(true);
    authFutureMock.verify();
    EasyMock.expectLastCall();
    EasyMock.replay(sshClientMock, connectFutureMock, clientSessionMock,
        authFutureMock);

    SshClientConnector sshClientConnector =
        new SshClientConnector(sshConfiguration);
    ClientSession clientSession =
        sshClientConnector.connect(sshClientMock, host, port);

    assertEquals(clientSessionMock, clientSession);

    EasyMock.verify(sshClientMock, connectFutureMock, clientSessionMock,
        authFutureMock);
  }

  @Test
  public void testSudoCommandBuilder() throws Exception {
    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    String user = "user";
    String command = "echo command";
    String loginCommand = "exec sudo -iu {0} ; logout ; ";
    sshConfiguration.setLoginCommand(loginCommand);

    PipedInputStream pipedInputStream = new PipedInputStream();

    SSHConnector.SudoCommandStreamBuilder sudoCommandStreamBuilder =
        new SSHConnector.SudoCommandStreamBuilder(sshConfiguration);
    InputStream sudoCommandInputStream = sudoCommandStreamBuilder
        .buildSudoCommand(user, new ByteArrayInputStream(command.getBytes()),
            pipedInputStream);

    assertEquals("exec sudo -iu " + user + " ; logout ; " + command,
        new String(ByteStreams.toByteArray(sudoCommandInputStream)));
  }

  @Test
  public void testSshCommandSender() throws Exception {
    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    String user = "user";
    String host = "host";
    Integer port = 22;
    String command = "echo command";
    ByteArrayInputStream commandStream =
        new ByteArrayInputStream(command.getBytes());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Map<PtyMode, Integer> ptyModes = new HashMap<PtyMode, Integer>();

    ClientSession clientSessionMock = EasyMock.createMock(ClientSession.class);
    ChannelShell channelShellMock = EasyMock.createMock(ChannelShell.class);
    OpenFuture openFuture = EasyMock.createMock(OpenFuture.class);
    CloseFuture closeFutureMock = EasyMock.createMock(CloseFuture.class);
    EasyMock.expect(clientSessionMock.createShellChannel())
        .andReturn(channelShellMock);
    channelShellMock.setupSensibleDefaultPty();
    EasyMock.expectLastCall();
    EasyMock.expect(channelShellMock.getPtyModes()).andReturn(ptyModes);
    channelShellMock.setIn(EasyMock.anyObject(InputStream.class));
    EasyMock.expectLastCall();
    channelShellMock.setOut(EasyMock.anyObject(OutputStream.class));
    EasyMock.expectLastCall();
    channelShellMock.setErr(EasyMock.anyObject(OutputStream.class));
    EasyMock.expectLastCall();
    EasyMock.expect(channelShellMock.open()).andReturn(openFuture);
    EasyMock
        .expect(openFuture.await(sshConfiguration.getTunnelConnectTimeout()))
        .andReturn(true);
    EasyMock.expect(channelShellMock.waitFor(ClientChannel.CLOSED,
        sshConfiguration.getTunnelConnectTimeout())).andReturn(ClientChannel.CLOSED);
    EasyMock.expect(channelShellMock.getExitStatus()).andReturn(0);
    EasyMock.expect(channelShellMock.close(true)).andReturn(closeFutureMock);

    EasyMock.replay(clientSessionMock, channelShellMock, openFuture);

    Integer exitstatus = new SSHConnector.SshCommandSender(sshConfiguration,
        new SSHConnector.ChannelShellPtyModesSetter())
        .sendCommand(clientSessionMock, commandStream, out, out);

    assertEquals(0, exitstatus.intValue());
    assertEquals(ptyModes.get(PtyMode.ECHO), new Integer(1));
    EasyMock.verify(clientSessionMock, channelShellMock, openFuture);
  }

  @Test(expected = SSHConnector.SshClientConnectionFailedException.class)
  public void testSshCommandSenderConnectionFailed() throws Exception {
    SSHConfiguration sshConfiguration = new SSHConfiguration();
    sshConfiguration.setTunnelConnectTimeout(0);
    String user = "user";
    String host = "host";
    Integer port = 22;
    String command = "echo command";
    ByteArrayInputStream commandStream =
        new ByteArrayInputStream(command.getBytes());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Map<PtyMode, Integer> ptyModes = new HashMap<PtyMode, Integer>();

    ClientSession clientSessionMock = EasyMock.createMock(ClientSession.class);
    ChannelShell channelShellMock = EasyMock.createMock(ChannelShell.class);
    OpenFuture openFuture = EasyMock.createMock(OpenFuture.class);
    CloseFuture closeFutureMock = EasyMock.createMock(CloseFuture.class);
    EasyMock.expect(clientSessionMock.createShellChannel())
        .andReturn(channelShellMock);
    channelShellMock.setupSensibleDefaultPty();
    EasyMock.expectLastCall();
    EasyMock.expect(channelShellMock.getPtyModes()).andReturn(ptyModes);
    channelShellMock.setIn(EasyMock.anyObject(InputStream.class));
    EasyMock.expectLastCall();
    channelShellMock.setOut(EasyMock.anyObject(OutputStream.class));
    EasyMock.expectLastCall();
    channelShellMock.setErr(EasyMock.anyObject(OutputStream.class));
    EasyMock.expectLastCall();
    EasyMock.expect(channelShellMock.open()).andReturn(openFuture);
    EasyMock
        .expect(openFuture.await(sshConfiguration.getTunnelConnectTimeout()))
        .andReturn(false);
    EasyMock.expect(openFuture.getException()).andReturn(new IOException());
    EasyMock.expect(channelShellMock.close(true)).andReturn(closeFutureMock);

    EasyMock.replay(clientSessionMock, channelShellMock, openFuture);

    new SSHConnector.SshCommandSender(sshConfiguration,
        new SSHConnector.ChannelShellPtyModesSetter())
        .sendCommand(clientSessionMock, commandStream, out, out);

    EasyMock.verify(clientSessionMock, channelShellMock, openFuture);
  }
}
