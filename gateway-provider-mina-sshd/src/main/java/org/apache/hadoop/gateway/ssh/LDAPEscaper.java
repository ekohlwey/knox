package org.apache.hadoop.gateway.ssh;

public class LDAPEscaper {
  /*
   * * 0x2a ( 0x28 ) 0x29 \ 0x5c NUL 0x00
   */
  private static final char[] ESCAPABLE_CHARS = { '*', '(', ')', '\\', '\0' };
  private static final char[][] ASCII_VERSIONS = { { '2', 'a' }, { '2', '8' },
      { '2', '9' }, { '5', 'c' }, { '0', '0' } };

  public String escape(final String input) {
    if (input == null) {
      return null;
    }
    int replaceChars = 0;
    for (int i = 0; i < input.length(); i++) {
      for (int j = 0; j < ESCAPABLE_CHARS.length; j++) {
        if (input.charAt(i) == ESCAPABLE_CHARS[j]) {
          replaceChars++;
        }
      }
    }
    final char[] newChars = new char[input.length() + replaceChars * 3];
    for (int i = 0; i < input.length(); i++) {
      for (int j = 0; j < ESCAPABLE_CHARS.length; j++) {
        if (input.charAt(i) == ESCAPABLE_CHARS[j]) {
          newChars[i] = '\\';
          newChars[i + 1] = ASCII_VERSIONS[j][0];
          newChars[i + 2] = ASCII_VERSIONS[j][1];
        } else {
          newChars[i] = input.charAt(i);
        }
      }
    }
    return new String(newChars);
  }
}
