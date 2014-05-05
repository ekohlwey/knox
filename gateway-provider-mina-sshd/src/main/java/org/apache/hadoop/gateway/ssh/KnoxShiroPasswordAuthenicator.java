package org.apache.hadoop.gateway.ssh;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.UserAuth;
import org.apache.sshd.server.auth.UserAuthPassword;
import org.apache.sshd.server.session.ServerSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
public class KnoxShiroPasswordAuthenicator implements PasswordAuthenticator {
  private static Logger LOG = LoggerFactory.getLogger(KnoxShiroPasswordAuthenicator.class);

  public static class ShiroPasswordAuthenticator {

    public boolean auth(Subject currentUser, String username, String password) {
      // let's login the current user so we can check against roles and permissions:
      if (!currentUser.isAuthenticated()) {
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        token.setRememberMe(true);
        try {
          currentUser.login(token);
        } catch (UnknownAccountException uae) {
          LOG.info("There is no user with username of " + token.getPrincipal());
          return false;
        } catch (IncorrectCredentialsException ice) {
          LOG.info("Password for account " + token.getPrincipal() + " was incorrect!");
          return false;
        } catch (LockedAccountException lae) {
          LOG.info("The account for username " + token.getPrincipal() + " is locked.  " +
              "Please contact your administrator to unlock it.");
          return false;
        }
        catch (AuthenticationException ae) {
          LOG.error("Exception occurred authenticating user " + token.getPrincipal(), ae);
          return false;
        }
      }
      return true;
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
