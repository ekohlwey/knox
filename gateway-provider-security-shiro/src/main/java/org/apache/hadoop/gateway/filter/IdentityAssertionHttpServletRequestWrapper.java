package org.apache.hadoop.gateway.filter;

import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Map;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class IdentityAssertionHttpServletRequestWrapper extends
    HttpServletRequestWrapper {

  private static final String PRINCIPAL_PARAM = "user.name";
  
  String username = null;

  public IdentityAssertionHttpServletRequestWrapper(HttpServletRequest request, String principal) {
    super(request);
    username = principal;
  }

  @Override
  public String getParameter(String name) {
    if (name.equals(PRINCIPAL_PARAM)) {
      return username;
    }
    return super.getParameter(name);
  }
  
  @SuppressWarnings("rawtypes")
  @Override
  public Map getParameterMap() {
    return getParams();
  }

  @SuppressWarnings({ "unchecked", "rawtypes" })
  @Override
  public Enumeration getParameterNames() {
    Map<String, String[]> params = getParams();
    Enumeration<String> e = Collections.enumeration((Collection<String>) params);

    return e;
  }

  @Override
  public String[] getParameterValues(String name) {
    Map<String, String[]> params = getParams();

    return params.get(name);
  }

  private Map<String, String[]> getParams( String qString ) {
    if (qString == null || qString.length() == 0) return null;
    Map<String, String[]> params = parseQueryString(qString);
    ArrayList<String> al = new ArrayList<String>();
    al.add(username);
    String[] a = {""};
    params.put(PRINCIPAL_PARAM, al.toArray(a));

    return params;
  }

  private Map<String, String[]> getParams() {
    return getParams( super.getQueryString() );
  }
  
  @Override
  public String getQueryString() {
    String q = null;
    Map<String, String[]> params = getParams();
    if (params != null) {
      q = urlEncodeUTF8( params );
    }
    return q;
  }

  @Override
  public ServletInputStream getInputStream() throws java.io.IOException {
    String contentType = getContentType();
    if( contentType != null && contentType.startsWith( "application/x-www-form-urlencoded" ) ) {
      String encoding = getCharacterEncoding();
      if( encoding == null ) {
        encoding = Charset.defaultCharset().name();
      }
      String body = IOUtils.toString( super.getInputStream(), encoding );
      Map<String, String[]> params = getParams( body );
      body = urlEncode( params, encoding );
      return new ServletInputStreamWrapper( new ByteArrayInputStream( body.getBytes( encoding ) ) );
    } else {
      return super.getInputStream();
    }
  }

  static String urlEncodeUTF8(String s) {
    return urlEncode( s, "UTF-8" );
  }

  static String urlEncode( String string, String encoding ) {
    try {
      return URLEncoder.encode( string, encoding );
    } catch (UnsupportedEncodingException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  static String urlEncodeUTF8( Map<String,String[]> params ) {
    return urlEncode( params, "UTF-8" );
  }

  static String urlEncode( Map<String,String[]> map, String encoding ) {
    StringBuilder sb = new StringBuilder();
    for (Map.Entry<?,?> entry : map.entrySet()) {
        if (sb.length() > 0) {
            sb.append("&");
        }
        String[] values = (String[]) entry.getValue();
        for (int i = 0; i < values.length; i++) {
          if (values[i] != null) {
            try {
            sb.append(String.format("%s=%s",
                urlEncode( entry.getKey().toString(), encoding ),
                urlEncode( values[i], encoding )
            ));
            }
            catch (IllegalArgumentException e) {
              e.printStackTrace();
              System.out.println("SKIPPING PARAM: " + entry.getKey().toString() + " with value: " + values[i]);
            }
          }
        }
    }
    return sb.toString();       
}  
  
  @SuppressWarnings({ "deprecation", "unchecked" })
  private static Map<String,String[]> parseQueryString( String queryString ) {
    return javax.servlet.http.HttpUtils.parseQueryString( queryString );
  }
  
  private class ServletInputStreamWrapper extends ServletInputStream {

    private InputStream stream;

    private ServletInputStreamWrapper( InputStream stream ) {
      this.stream = stream;
    }

    @Override
    public int read() throws IOException {
      return stream.read();
    }

  }

}
