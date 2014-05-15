package org.apache.hadoop.gateway.ssh.auth;

import org.apache.hadoop.gateway.i18n.messages.MessagesFactory;
import org.apache.hadoop.gateway.ssh.SshGatewayMessages;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.session.ServerSession;

/**
 *
 */
public class KnoxShiroPasswordAuthenicator implements PasswordAuthenticator {
  private static SshGatewayMessages LOG = MessagesFactory.get(SshGatewayMessages.class);

  public static class ShiroPasswordAuthenticator {

    public boolean auth(Subject currentUser, String username, String password) {
      // let's login the current user so we can check against roles and permissions:
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        token.setRememberMe(true);
        try {
          currentUser.login(token);
          LOG.userAuthenticated(username);
          return true;
        } catch (UnknownAccountException uae) {
          LOG.userUnknown(username);
          return false;
        } catch (IncorrectCredentialsException ice) {
          LOG.userUnauthenticated(username);
          return false;
        } catch (LockedAccountException lae) {
          LOG.userAccountLocked(username);
          return false;
        } catch (AuthenticationException ae) {
          LOG.userUnauthenticated(username);
          return false;
        } finally {
          token.clear();
        }
    }
  }

  private final ShiroPasswordAuthenticator shiroPasswordAuthenticator;

  public KnoxShiroPasswordAuthenicator(
      ShiroPasswordAuthenticator shiroPasswordAuthenticator) {
    this.shiroPasswordAuthenticator = shiroPasswordAuthenticator;
  }

  @Override
  public boolean authenticate(String username, String password,
                              ServerSession session) {
    return shiroPasswordAuthenticator.auth(SecurityUtils.getSubject(),
        username, password);
  }
}
