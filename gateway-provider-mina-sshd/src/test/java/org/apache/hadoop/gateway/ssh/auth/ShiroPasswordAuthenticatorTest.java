package org.apache.hadoop.gateway.ssh.auth;

import static org.junit.Assert.*;

import org.apache.hadoop.gateway.ssh.auth.KnoxShiroPasswordAuthenicator;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Test;

public class ShiroPasswordAuthenticatorTest {

  @Test
  public void testShiroPasswordAuthLogin() throws Exception {

    Subject subjectMock = EasyMock.createMock(Subject.class);
    final String[] userPwd = new String[2];
    Capture<UsernamePasswordToken> tokenCapture = new Capture<UsernamePasswordToken>() {
      @Override
      public void setValue(UsernamePasswordToken value) {
        super.setValue(value);
        userPwd[0] = value.getUsername();
        userPwd[1] = new String(value.getPassword());
      }
    };
    subjectMock.login(EasyMock.capture(tokenCapture));
    EasyMock.expectLastCall();
    EasyMock.replay(subjectMock);

    String user = "user";
    String pwd = "pwd";
    boolean auth =
        new KnoxShiroPasswordAuthenicator.ShiroPasswordAuthenticator()
            .auth(subjectMock, user, pwd);
    assertTrue(auth);

    EasyMock.verify(subjectMock);

    UsernamePasswordToken usernamePasswordToken = tokenCapture.getValue();
    //verify that the token has been cleared
    assertNull(usernamePasswordToken.getUsername());
    assertNull(usernamePasswordToken.getPassword());
    assertEquals(user, userPwd[0]);
    assertEquals(pwd, userPwd[1]);
  }

  @Test
  public void testShiroPasswordAuthLoginFailed() throws Exception {

    Subject subjectMock = EasyMock.createMock(Subject.class);
    final String[] userPwd = new String[2];
    Capture<UsernamePasswordToken> tokenCapture = new Capture<UsernamePasswordToken>() {
      @Override
      public void setValue(UsernamePasswordToken value) {
        super.setValue(value);
        userPwd[0] = value.getUsername();
        userPwd[1] = new String(value.getPassword());
      }
    };
    subjectMock.login(EasyMock.capture(tokenCapture));
    EasyMock.expectLastCall().andThrow(new AuthenticationException());
    EasyMock.replay(subjectMock);

    String user = "user";
    String pwd = "pwd";
    boolean auth =
        new KnoxShiroPasswordAuthenicator.ShiroPasswordAuthenticator()
            .auth(subjectMock, user, pwd);
    assertFalse(auth);

    EasyMock.verify(subjectMock);

    UsernamePasswordToken usernamePasswordToken = tokenCapture.getValue();
    //verify that the token has been cleared
    assertNull(usernamePasswordToken.getUsername());
    assertNull(usernamePasswordToken.getPassword());
    assertEquals(user, userPwd[0]);
    assertEquals(pwd, userPwd[1]);
  }
}