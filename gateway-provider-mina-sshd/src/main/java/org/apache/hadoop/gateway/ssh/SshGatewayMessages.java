package org.apache.hadoop.gateway.ssh;

import org.apache.hadoop.gateway.i18n.messages.Message;
import org.apache.hadoop.gateway.i18n.messages.MessageLevel;
import org.apache.hadoop.gateway.i18n.messages.Messages;
import org.apache.hadoop.gateway.i18n.messages.StackTrace;
import org.apache.shiro.config.Ini;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
@Messages(logger = "org.apache.hadoop.gateway.ssh")
public interface SshGatewayMessages {

  @Message(level = MessageLevel.DEBUG, text = "Starting shiro authentication with configuration: {0}.")
  void shiroConfiguration(Ini ini);

  @Message(level = MessageLevel.DEBUG, text = "Starting ssh gateway with configuration: {0}.")
  void configuration(SSHConfiguration sshConfiguration);

  @Message(level = MessageLevel.INFO, text = "Started ssh gateway on port {0}.")
  void startedGateway(int port);

  @Message(level = MessageLevel.INFO, text = "Stopped ssh gateway.")
  void stoppedGateway();

  @Message(level = MessageLevel.FATAL,
      text = "Failed to start ssh gateway: {0}")
  void failedToStartGateway(
      @StackTrace(level = MessageLevel.DEBUG) Throwable e);

  @Message(level = MessageLevel.DEBUG, text = "User {0} authenticated")
  void userAuthenticated(String user);

  @Message(level = MessageLevel.DEBUG, text = "User {0} unauthenticated")
  void userUnauthenticated(String user);

  @Message(level = MessageLevel.DEBUG, text = "User {0} unknown")
  void userUnknown(String user);

  @Message(level = MessageLevel.DEBUG, text = "User {0} account locked")
  void userAccountLocked(String user);

  @Message(level = MessageLevel.FATAL,
      text = "Error connecting to remote ssh server: {0}. Stack trace: {1}")
  void failedConnectingToRemote(String host,
      @StackTrace(level = MessageLevel.DEBUG) Exception e);
}
