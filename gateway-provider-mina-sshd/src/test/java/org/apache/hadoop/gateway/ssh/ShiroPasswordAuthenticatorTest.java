package org.apache.hadoop.gateway.ssh;

import static org.junit.Assert.*;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Test;

public class ShiroPasswordAuthenticatorTest {

  @Test
  public void testShiroPasswordAuthAlreadyAuthenticated() throws Exception {

    Subject subjectMock = EasyMock.createMock(Subject.class);
    EasyMock.expect(subjectMock.isAuthenticated()).andReturn(true);
    EasyMock.replay(subjectMock);

    boolean auth =
        new KnoxShiroPasswordAuthenicator.ShiroPasswordAuthenticator()
            .auth(subjectMock, "", "");
    assertTrue(auth);

    EasyMock.verify(subjectMock);
  }

  @Test
  public void testShiroPasswordAuthLogin() throws Exception {

    Subject subjectMock = EasyMock.createMock(Subject.class);
    EasyMock.expect(subjectMock.isAuthenticated()).andReturn(false);
    Capture<UsernamePasswordToken> tokenCapture = new Capture<UsernamePasswordToken>();
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
    assertEquals(user, usernamePasswordToken.getUsername());
    assertArrayEquals(pwd.toCharArray(), usernamePasswordToken.getPassword());
  }

  @Test
  public void testShiroPasswordAuthLoginFailed() throws Exception {

    Subject subjectMock = EasyMock.createMock(Subject.class);
    EasyMock.expect(subjectMock.isAuthenticated()).andReturn(false);
    Capture<UsernamePasswordToken> tokenCapture = new Capture<UsernamePasswordToken>();
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
    assertEquals(user, usernamePasswordToken.getUsername());
    assertArrayEquals(pwd.toCharArray(), usernamePasswordToken.getPassword());
  }
}