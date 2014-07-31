package org.apache.hadoop.gateway.ssh.util;

import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.nio.charset.Charset;

import org.apache.sshd.common.util.NoCloseOutputStream;

/**
 * InputStream line reader that handles character conversions correctly
 */
public class LineReaderInputStream extends FilterInputStream {

  private final Reader inputStreamReader;
  private final OutputStream echo;
  private final Charset charset;
  private final StringBuilder stringBuilder = new StringBuilder();

  public LineReaderInputStream(InputStream in, OutputStream echo,
      String charsetName) {
    super(in);
    this.charset = Charset.forName(charsetName);
    inputStreamReader = new InputStreamReader(in, charset);
    this.echo = echo;
  }

  public String readLine() throws IOException {
    // -> \n - emit buffer
    // -> ^D (4) - end
    // -> END (-1) - end
    // -> ^H (8) - remove last character
    boolean continueReading = true;
    boolean closeStream = false;
    int readCharacter;
    Writer outputWriter = null;
    try {
      outputWriter = new OutputStreamWriter(new NoCloseOutputStream(echo));
      while (continueReading) {
        switch (readCharacter = inputStreamReader.read()) {
        case '\u0004': // end of stream or ctrl-d
        case -1:
          continueReading = false;
          closeStream = true;
          break;
        case '\u0008': // backspace
        case '\u007f':
          if (stringBuilder.length() > 0) {
            stringBuilder.setLength(stringBuilder.length() - 1);
            outputWriter.write("\u0008 \u0008");
          }
          break;
        case '\n':
        case '\r':
          continueReading = false;
          outputWriter.write(readCharacter);
          break;
        default:
          // don't track control characters other than the ones mentioned above
          if((readCharacter >=0 && readCharacter <='\u001f')||(readCharacter>='\u0080'&&readCharacter<='\u009f')){
            break;
          }
          stringBuilder.append((char)readCharacter);
          outputWriter.write(readCharacter);
          break;
        }
        outputWriter.flush();
      }
    } finally {
      if (outputWriter != null) {
        outputWriter.close();
      }
    }
    if (closeStream) {
      return null;
    }
    String finalString = new String(stringBuilder);
    stringBuilder.setLength(0);
    return finalString;
  }

  @Override
  public void close() throws IOException {
    inputStreamReader.close();
  }
}
