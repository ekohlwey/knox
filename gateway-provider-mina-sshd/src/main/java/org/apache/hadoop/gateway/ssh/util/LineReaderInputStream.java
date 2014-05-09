package org.apache.hadoop.gateway.ssh.util;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PushbackReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;

/**
 * InputStream line reader that handles character conversions correctly
 */
public class LineReaderInputStream extends FilterInputStream {

  private Reader inputStreamReader;

  public LineReaderInputStream(InputStream in) {
    super(in);
    inputStreamReader = new InputStreamReader(in);
  }

  public LineReaderInputStream(InputStream in, String charsetName)
      throws UnsupportedEncodingException {
    super(in);
    inputStreamReader = new InputStreamReader(in, charsetName);
  }

  public String readLine() throws IOException {
    return readLine(null);
  }

  /**
   *
   * @param echo Echo each character to the echo stream.
   * @return line from the underlying input stream
   * @throws IOException
   */
  public String readLine(OutputStream echo) throws IOException {
    ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();

    boolean read = true;
    boolean closed = false;
    int c;
    while (read) {
      switch (c = inputStreamReader.read()) {
        case 4: //EOT or Ctrl-d
        case -1:
          read = false;
          closed = true;
          break;
        case '\n':
          read = false;
          if(echo != null) {echo.write(c);}
          break;
        case '\r':
          if(inputStreamReader.ready()) {
            int c2 = inputStreamReader.read();
            if ((c2 != '\n') && (c2 != -1)) {
              if (!(inputStreamReader instanceof PushbackReader)) {
                this.inputStreamReader = new PushbackReader(inputStreamReader);
              }
              ((PushbackReader) inputStreamReader).unread(c2);
            }
          }
          read = false;
          if(echo != null) {echo.write(c);}
          break;
        default:
          bytesOut.write(c);
          if(echo != null) {echo.write(c);}
          break;
      }
    }

    if(closed) {
      return null;
    }

    return new String(bytesOut.toByteArray());
  }

  @Override
  public void close() throws IOException {
    inputStreamReader.close();
  }
}
