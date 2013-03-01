/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.gateway.util.urltemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Builder {

  private boolean hasScheme;
  private Scheme scheme;
  private boolean hasAuthority;
  private boolean isAuthorityOnly;
  private Username username;
  private Password password;
  private Host host;
  private Port port;
  private boolean isAbsolute;
  private boolean isDirectory;
  private List<Path> path;
  private boolean hasQuery;
  private LinkedHashMap<String,Query> query;
  private Query extra;
  private boolean hasFragment;
  private Fragment fragment;

  public Builder() {
    this.hasScheme = false;
    this.scheme = null;
    this.hasAuthority = false;
    this.isAuthorityOnly = false;
    this.username = null;
    this.password = null;
    this.host = null;
    this.port = null;
    this.isAbsolute = false;
    this.isDirectory = false;
    this.path = new ArrayList<Path>();
    this.hasQuery = false;
    this.query = new LinkedHashMap<String,Query>();
    this.extra = null;
    this.hasFragment = false;
    this.fragment = null;
  }

  public Builder( Template template ) {
    this.hasScheme = template.hasScheme();
    this.scheme = copyScheme( template.getScheme() );
    this.hasAuthority = template.hasAuthority();
    this.isAuthorityOnly = template.isAuthorityOnly();
    this.username = copyUsername( template.getUsername() );
    this.password = copyPassword( template.getPassword() );
    this.host = copyHost( template.getHost() );
    this.port = copyPort( template.getPort() );
    this.isAbsolute = template.isAbsolute();
    this.isDirectory = template.isDirectory();
    this.path = copyPath( template.getPath() );
    this.hasQuery = template.hasQuery();
    this.query = copyQuery( template.getQuery() );
    this.extra = copyExtra( template.getExtra() );
    this.hasFragment = template.hasFragment();
    this.fragment = copyFragment( template.getFragment() );
  }

  private Scheme copyScheme( Scheme orig ) {
    Scheme copy = null;
    if( orig != null ) {
      copy = new Scheme( orig );
    }
    return copy;
  }

  private Username copyUsername( Username orig ) {
    Username copy = null;
    if( orig != null ) {
      copy = new Username( orig );
    }
    return copy;
  }

  private Password copyPassword( Password orig ) {
    Password copy = null;
    if( orig != null ) {
      copy = new Password( orig );
    }
    return copy;
  }

  private Host copyHost( Host orig ) {
    Host copy = null;
    if( orig != null ) {
      copy = new Host( orig );
    }
    return copy;
  }

  private Port copyPort( Port orig ) {
    Port copy = null;
    if( orig != null ) {
      copy = new Port( orig );
    }
    return copy;
  }

  private Query copyExtra( Query orig ) {
    Query copy = null;
    if( orig != null ) {
      copy = new Query( orig );
    }
    return copy;
  }

  private List<Path> copyPath( List<Path> orig ) {
    List<Path> copy = new ArrayList<Path>();
    if( orig != null ) {
      for( Path path : orig ) {
        copy.add( new Path( path ) );
      }
    }
    return copy;
  }

  private Fragment copyFragment( Fragment orig ) {
    Fragment copy = null;
    if( orig != null ) {
      copy = new Fragment( orig );
    }
    return copy;
  }

  private LinkedHashMap<String, Query> copyQuery( Map<String, Query> orig ) {
    LinkedHashMap<String,Query> copy = new LinkedHashMap<String, Query>();
    if( orig != null ) {
      for( Map.Entry<String,Query> entry : orig.entrySet() ) {
        copy.put( entry.getKey(), new Query( entry.getValue() ) );
      }
    }
    return copy;
  }

  public Template build() {
    return new Template(
        scheme, hasScheme,
        username, password, host, port, hasAuthority, isAuthorityOnly,
        path, isAbsolute, isDirectory,
        query, extra, hasQuery,
        fragment, hasFragment );
  }

  public boolean getHashScheme() {
    return this.hasScheme;
  }

  public void setHasScheme( boolean hasScheme ) {
    this.hasScheme = hasScheme;
    if( !hasScheme ) {
      scheme = null;
    }
  }

  public Scheme getScheme() {
    return this.scheme;
  }

  public void setScheme( String paramName, String valuePattern ) {
    this.scheme = new Scheme( paramName, valuePattern );
    setHasScheme( true );
  }

  public boolean getHasAuthority() {
    return hasAuthority;
  }

  public void setHasAuthority( boolean hasAuthority ) {
    this.hasAuthority = hasAuthority;
  }

  public boolean getIsAuthorityOnly() {
    return isAuthorityOnly;
  }

  public void setIsAuthorityOnly( boolean isAuthorityOnly ) {
    this.isAuthorityOnly = isAuthorityOnly;
  }

  public Username getUsername() {
    return username;
  }

  public void setUsername( String paramName, String valuePattern ) {
    setHasAuthority( true );
    username = new Username( paramName, valuePattern );
  }

  public Password getPassword() {
    return password;
  }

  public void setPassword( String paramName, String valuePattern ) {
    setHasAuthority( true );
    password = new Password( paramName, valuePattern );
  }

  public Host getHost() {
    return host;
  }

  public void setHost( String paramName, String valuePattern ) {
    setHasAuthority( true );
    host = new Host( paramName, valuePattern );
  }

  public Port getPort() {
    return port;
  }

  public void setPort( String paramName, String valuePattern ) {
    setHasAuthority( true );
    port = new Port( paramName, valuePattern );
  }

  public boolean getIsAbsolute() {
    return isAbsolute;
  }

  public Builder setIsAbsolute( boolean isAbsolute ) {
    this.isAbsolute = isAbsolute;
    return this;
  }

  public boolean getIsDirectory() {
    return isDirectory;
  }

  public Builder setIsDirectory( boolean isDirectory ) {
    this.isDirectory = isDirectory;
    return this;
  }

  public List<Path> getPath() {
    return path;
  }

  public Builder addPath( String paramName, String valuePattern ) {
    Path segment = new Path( paramName, valuePattern );
    path.add( segment );
    return this;
  }

  public boolean getHasQuery() {
    return hasQuery;
  }

  public Builder setHasQuery( boolean hasQuery ) {
    this.hasQuery = hasQuery;
    return this;
  }

  public Map<String,Query> getQuery() {
    return this.query;
  }

  public Builder addQuery( String queryName, String paramName, String valuePattern ) {
    if( Segment.STAR_PATTERN.equals( queryName ) || Segment.GLOB_PATTERN.equals( queryName ) ) {
      if( extra == null ) {
        Query segment = new Query( queryName, paramName, valuePattern );
        extra = segment;
      } else {
        // Can't have two extras: ?{*}&{**}
        //TODO throw new URISyntaxException()? because
      }
    } else {
      Query segment = query.get( queryName );
      if( segment == null ) {
        segment = new Query( queryName, paramName, valuePattern );
        query.put( queryName, segment );
      } else {
        // Can't have two queryParam names for the same query name: ?query={param1}&query={param2} in a template.
        // Should probably throw an exception in this case.  However, you can have this in a valid URL.
        // This causes a problem with how templates are used for both URLs and Templates.
        // For a template only the first parameter name will be used.
        segment.addValue( valuePattern );
      }
    }
    return this;
  }

  public boolean getHasFragment() {
    return hasFragment;
  }

  public void setHasFragment( boolean hasFragment ) {
    this.hasFragment = hasFragment;
  }

  public Fragment getFragment() {
    return fragment;
  }

  public void setFragment( String paramName, String valuePattern ) {
    setHasFragment( true );
    this.fragment = new Fragment( paramName, valuePattern );
  }

}
