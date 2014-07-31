package org.apache.hadoop.gateway.ssh.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import org.apache.commons.io.output.NullOutputStream;
import org.easymock.EasyMock;
import org.junit.Test;

public class LineReaderInputStreamTest {

  @Test
  public void testReadLine() throws Exception {
    String data = "data\ndata2\n";

    LineReaderInputStream lineReader =
        new LineReaderInputStream(new ByteArrayInputStream(data.getBytes()), null, "UTF-8");

    assertEquals("data", lineReader.readLine());
    assertEquals("data2", lineReader.readLine());
    assertNull(lineReader.readLine());
  }

  @Test
  public void testCRNL() throws Exception {
    String data = "data\r\ndata2\n";

    LineReaderInputStream lineReader =
        new LineReaderInputStream(new ByteArrayInputStream(data.getBytes()), null, "UTF-8");

    assertEquals("data", lineReader.readLine());
    assertEquals("data2", lineReader.readLine());
    assertNull(lineReader.readLine());
  }

  @Test
  public void testLastLineNull() throws Exception {
    String data = "data\ndata2";

    LineReaderInputStream lineReader =
        new LineReaderInputStream(new ByteArrayInputStream(data.getBytes()), null, "UTF-8");

    assertEquals("data", lineReader.readLine());
    assertEquals(null, lineReader.readLine());
    assertNull(lineReader.readLine());
  }

  @Test
  public void testEndofTransmission() throws Exception {
    String data = "data\n\u0004data2\n";

    LineReaderInputStream lineReader =
        new LineReaderInputStream(new ByteArrayInputStream(data.getBytes()), null, "UTF-8");

    assertEquals("data", lineReader.readLine());
    assertEquals(null, lineReader.readLine());
  }

  @Test
  public void testEcho() throws Exception {
    String data = "data\ndata2\n";

    ByteArrayOutputStream echo = new ByteArrayOutputStream();
    LineReaderInputStream lineReader =
        new LineReaderInputStream(new ByteArrayInputStream(data.getBytes()), echo, "UTF-8");

    assertEquals("data", lineReader.readLine());
    assertEquals("data\n", new String(echo.toByteArray()));
    echo.reset();
    assertEquals("data2", lineReader.readLine());
    assertEquals("data2\n", new String(echo.toByteArray()));
    assertNull(lineReader.readLine());
  }

  @Test
  public void testEncoding() throws Exception {
    String data = "data\ndata2\n";

    String encoding = "UTF-16BE";
    LineReaderInputStream lineReader = new LineReaderInputStream(
        new ByteArrayInputStream(data.getBytes(encoding)), null, encoding);

    assertEquals("data", lineReader.readLine());
    assertEquals("data2", lineReader.readLine());
    assertNull(lineReader.readLine());
  }

  @Test
  public void testEmpty() throws Exception {

    LineReaderInputStream lineReader =
        new LineReaderInputStream(new ByteArrayInputStream(new byte[0]), new NullOutputStream(), "UTF-8");

    assertNull(lineReader.readLine());
  }

  @Test
  public void testClose() throws Exception {

    InputStream inputStreamMock = EasyMock.createMock(InputStream.class);
    EasyMock.expect(inputStreamMock
        .read((byte[]) EasyMock.anyObject(), EasyMock.anyInt(),
            EasyMock.anyInt())).andReturn(-1);
    inputStreamMock.close();
    EasyMock.expectLastCall();
    EasyMock.replay(inputStreamMock);

    LineReaderInputStream lineReader =
        new LineReaderInputStream(inputStreamMock, null, null);

    assertNull(lineReader.readLine());
    lineReader.close();

    EasyMock.verify(inputStreamMock);
  }

}