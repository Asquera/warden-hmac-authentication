# HMAC

This gem provides request authentication via [HMAC](http://en.wikipedia.org/wiki/Hmac). The main usage is request based, noninteractive
authentication for API implementations. Two strategies are supported that differ mainly in how the authentication information is
transferred to the server: One header-based authentication method and one query-based. The authentication scheme is in some parts based
on ideas laid out in this article and the following discussion: 
http://broadcast.oreilly.com/2009/12/principles-for-standardized-rest-authentication.html

The gem also provides a small helper class that can be used to generate request signatures.

## Header-Based authentication

The header-based authentication transports the authentication information in the (misnamed) `Authorization` HTTP-Header. The primary 
advantage of header-based authentication is that request urls are stable even if authentication information changes. This improves
cacheability of the resource.

Header-based authentication is supported by the `:hmac_header` strategy.

## Query-Based authentication

Query-Based authentication encodes all authentication in the query string. Query-based authentication has unique advantages in 
scenarios with little or no control over the request headers such as pre-generating and embedding a signed URL in a web-page or 
similar cases. However, resources requested using query-based authentication cannot be cached since the request URL changes for
every request.
All information related to authentication is passed as a single hash in one single query parameter to minimize collisions with other
query parameters. The name of the query parameter defaults to `auth` and can be controlled using the `:auth_parameter` config option.
Query-based authentication takes optional headers into account if they are present in the request.

Query-based authentication is supported by the `:hmac_query` strategy.

## Shared secret

Both strategies use a secret that is shared between the server and the client to calculate the signature. The secret must be
configured when registering the strategy. For simple cases a single secret may be sufficient but most real-world scenarios
will require a different secret for each possible client. Such cases can be managed by passing a Proc as secret. An empty
secret (empty string or nil) will trigger authentication failure.


## Warden strategy usage

Both strategies can be used at the same time and will not interfere with each other. It is advisable to attempt query-based
authentication first to reduce the chance that a stray Authorization header triggers header-based authentication. Both strategies
read additional configuration from a hash named :hmac in the warden scope.

Configure the HMAC warden strategy:

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :hmac,  :strategies => [:hmac_query, :hmac_header], 
                                     :hmac => { 
                                       :secret => "secrit"
                                     }
    end



### Retrieving the secret from a database or other storage

If you want to retrieve the secret and token using a different strategy, either extend the HMAC strategy:

    class Warden::Strategies::HMACQuery < Warden::Strategies::HMACBase
      def retrieve_user
        User.get(request[:user_id])
      end

      def secret
        retrieve_user.secret
      end
    end

or use a Proc that retrieves the secret.

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :hmac, :strategies => [:hmac_query, :hmac_header], 
                                     :store => false, 
                                     :hmac => { 
                                       :secret => Proc.new {|strategy|
                                         "secret"
                                       }
                                     }
    end

### Retrieving the user from the database

If a callable object is given for the `:retrieve_user` option, this callable will be called after successful authentication. The callable must accept the strategy itself as its only argument. The strategy allows access to all request parameters and header as well as all derived values. The result will be memoized. 

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :hmac, :strategies => [:hmac_query, :hmac_header], 
                                     :store => false, 
                                     :hmac => { 
                                       :retrieve_user => Proc.new {|strategy|
                                         User.get(strategy.params["userid"])
                                       }
                                     }
    end

An alternative is overwriting the strategies `retrieve_user` method.

### Controlling the HMAC algorithm

The algorithm can be controlled using the `:algorithm` option:

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :hmac, :strategies => [:hmac_query, :hmac_header], 
                                     :hmac => { 
                                       :secret => "secrit",
                                       :algorithm => "md5"
                                     }
    end

The algorithm defaults to SHA1.

## Auth Scheme Name

The name of the authentication scheme is primarily used for header authentication. It is used to construct the `Authorization` header and 
must thus avoid names that are reserved for existing standardized authentication schemes such as `Basic` and `Digest`. The scheme
name is also used to construct the default values for various header names. The authentication scheme name defaults to `HMAC`

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :hmac, :strategies => [:hmac_query, :hmac_header], 
                                     :hmac => { 
                                       :secret => "secrit",
                                       :auth_scheme_name => "MyScheme"
                                     }
    end

No authentication attempt is made if the scheme name in the `Authorization` header does not match the configured scheme name.    

## Authentication Header Format

The format of the Authentication Header can be controlled using the `:auth_header_format` directive. The given format string will be interpolated
with all given options and the signature. The default value is `%{auth_scheme} %{signature}` which will result in an auth header with a format such as `HMAC 539263f4f83878a4917d2f9c1521320c28b926a9`. The format string must contain at least the `scheme` and `signature` components.

The `:auth_header_format` directive has a companion directive, `:auth_header_parse` which must be a regular expression. Any given regular expression will be evaluated against the authorization header. The results can be retrieved using the `parsed_auth_header` method. The regular expression must at least contain a pattern named `scheme` and pattern named `signature`. The default value for this directive is a regular expression that is auto-generated by translating the `:auth_header_format` setting to a regular expression that contains a named capture group for each named part of the format string. Each capture allows for word characters, plus, dash, underscore and dot. The default :auth_header_format `%{auth_scheme} %{signature}` will be translated to `/(?<auth_scheme>[-_+.\w]+) (?<signature>[-_+.\w]+)/`.
	
See the section about multiple authentication secrets for a use-case and a comprehensive example.	

## Optional nonce

An optional nonce can be passed in the request to increase security. The nonce is not limited to digits and can be any string. It's
advisable to limit the length of the nonce to a reasonable value. If a nonce is used it should be changed with every request. The
default header for the nonce is `X-#{auth-scheme-name}-Nonce` (`X-HMAC-Nonce`). The header name can be controlled using the `:nonce_header` 
configuration option.

The `:require_nonce` configuration can be set to `true` to enforce a nonce. If a nonce is required no authentication attempt will be
made for requests not providing a nonce.

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :hmac, :strategies => [:hmac_query, :hmac_header], 
                                     :hmac => { 
                                       :secret => "secrit",
                                       :require_nonce => true
                                     }
    end


## Required headers and parameters

Required headers and parameters must be present for a successful authentication attempt. The list of required headers defaults to 
the `Authorization` header for header-based authentication and is empty for query-based authentication. The list of required
parameters defaults to the chosen authentication parameter for query-based authentication and is empty for header-based authentication.
If a required parameter or header is not included in the request, no authentication attempt will be made for the strategy.

## Other optional headers

Some headers are optional but should be included in the signature of the request if present. The default list of optional headers
includes `Content-MD5` and `Content-Type`. The list of optional headers can be configured using the `:optional_headers` config option.
Optional headers are always included in the canonical representation if they are found in the request and not blank. Optional headers
will be included in the canonical representation for query-based authentication if they are present in the request so be careful 
not to include any header that is out of your clients control.

## Date and TTL

It is good practice to enforce a max-age for tokens. The hmac strategy allows this via the `ttl` parameter. It controls the max age 
of tokens in seconds and defaults to 900 seconds. Pass `nil` as ttl value to disable TTL checking.

The timestamp of the request is usually passed in the `Date` HTTP-Header. However, since some HTTP-Client libraries do not allow 
setting the Date header another header may be used to override the `Date` header. The name of this header can be controlled via the
`:alternate_date_header` option and defaults to `X-#{auth-scheme-name}-Date` (`X-HMAC-Date`). 

The date must be formatted as HTTP-Date according to RFC 1123, section 5.2.14 and should be provided in GMT time.

Example: Setting the ttl to 300 seconds:

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :token, :strategies => [:hmac_query, :hmac_header], 
                                     :hmac => { 
                                       :secret => "secrit",
                                       :ttl => 300 # make tokens valid for 5 minutes
                                     }
    end

### Clock Skew

The TTL allows for a little clock skew to accommodate servers that are slightly running off time. The allowed clock skew can be 
controlled with the `:clockskew` option and defaults to 5 seconds.


## Canonical representation

Both request methods use a canonical representation of the request together with the shared secret to calculate a signature 
that authenticates the request. The canonical representation is calculated using the following algorithm:

* Start with the empty string ("")
* Add the HTTP-Verb for the request ("GET", "POST", ...) in capital letters, followed by a single newline (U+000A).
* Add the date for the request using the form "date:#{date-of-request}" followed by a single newline. The date for the signature must be
formatted exactly as in the request.
* Add the nonce for the request in the form "nonce:#{nonce-in-request}" followed by a single newline. If no nonce is passed use the
empty string as nonce value.
* Convert all remaining header names to lowercase.
* Sort the remaining headers lexicographically by header name.
* Trim header values by removing any whitespace before the first non-whitespace character and after the last non-whitespace character.
* Combine lowercase header names and header values using a single colon (“:”) as separator. Do not include whitespace characters 
around the separator.
* Combine all headers using a single newline (U+000A) character and append them to the canonical representation, 
followed by a single newline (U+000A) character.
* Append the url-decoded query path to the canonical representation
* URL-decode query parameters if required
* If using query-based authentication: Remove all authentication-related parameters from the query parameters.
* Sort all query parameters lexicographically by parameter name and join them, using a single ampersand (“&”) as separator
* Append the query string using a single question mark (“?”) as separator unless the query string is empty

### Examples

Given the following request:

    GET /example/resource.html?sort=header%20footer&order=ASC HTTP/1.1
    Host: www.example.org
    Date: Mon, 20 Jun 2011 12:06:11 GMT
    User-Agent: curl/7.20.0 (x86_64-pc-linux-gnu) libcurl/7.20.0 OpenSSL/1.0.0a zlib/1.2.3
    X-MAC-Nonce: Thohn2Mohd2zugoo

The canonical representation is:

    GET\n
    date:Mon, 20 Jun 2011 12:06:11 GMT\n
    nonce:Thohn2Mohd2zugo\n
    /example/resource.html?order=ASC&sort=header footer


Given the following request:

    GET /example/resource.html?sort=header%20footer&order=ASC HTTP/1.1
    Host: www.example.org
    Date: Mon, 20 Jun 2011 12:06:11 GMT
    User-Agent: curl/7.20.0 (x86_64-pc-linux-gnu) libcurl/7.20.0 OpenSSL/1.0.0a zlib/1.2.3
    X-MAC-Nonce: Thohn2Mohd2zugoo
    X-MAC-Date: Mon, 20 Jun 2011 14:06:57 GMT

The canonical representation is:

    GET\n
    date:Mon, 20 Jun 2011 14:06:57 GMT\n
    nonce:Thohn2Mohd2zugo\n
    /example/resource.html?order=ASC&sort=header footer


### Generating the canonical representation for query-based authentication

The canonical representation for query-based authentication is generated using the same algorithm as for header-based authentication, but some
of the values are retrieved from the query string instead of the respective headers. All query parameters related to authentication
must be removed from the query string before generating the canonical representation.

#### Example

Given the following request:

    GET /example/resource.html?page=3&order=id%2casc&auth%5Bnonce%5D=foLiequei7oosaiWun5aoy8oo&auth%5Bdate%5D=Mon%2C+20+Jun+2011+14%3A06%3A57+GMT HTTP/1.1
    Host: www.example.org
    Date: Mon, 20 Jun 2011 12:06:11 GMT
    User-Agent: curl/7.20.0 (x86_64-pc-linux-gnu) libcurl/7.20.0 OpenSSL/1.0.0a zlib/1.2.3

The canonical representation is:

    GET\n 
    date:Mon, 20 Jun 2011 14:06:57 GMT\n
    nonce:foLiequei7oosaiWun5aoy8oo\n
    /example/resource.html?order=id,asc&page=3

## HMACSigner usage

The HMACSigner class can be used to validate and generate signatures for a given request. Most methods accept a hash as an intermediate 
representation of the request but some methods accept and operate on full urls.

    h = HMAC::Signer.new
    h.sign_url('http://example.org/example.html', 'secret')
    h.validate_url_signature('http://example.org/example.html?auth[signature]=foo', 'secret')

## Using multiple authentication secrets

Most applications will need to authenticate users using a combination of a user-identifier and and associated secret. 


### Header-Based Authentication

The format of the Autorization header can be controlled using the `:auth_header_format` option, the regular expression used to parse can be
set using `:auth_header_parse`. Combining these two options with a proc that retrieves the signing key from a storage authentication with multiple
secrets allows us to implement multiple signing keys:


    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :hmac, :strategies => [:hmac_query, :hmac_header], 
                                     :store => false, 
							         :hmac => {
							           :secret => Proc.new {|strategy|
							             keys = {
							               "KEY1" => 'secrit',
							               "KEY2" => "foo"
							             }
               
							             access_key_id = strategy.parsed_auth_header["access_key_id"]
							             keys[access_key_id]
							           },
							           :auth_header_format => '%{auth_scheme} %{access_key_id} %{signature}'							         }
    end

This combination of settings uses a slightly different Format for the authorization header and transports the secret keys ID in the header of the form `HMAC KEY2 a59456da1f61f86e96622e283780f58b7428c892`

Another option would be transporting the access key id in a separate header.

### Query-Based Authentication

The same result can be achieved using query-based auth by injecting extra authentication parameters and retrieving the access key in the proc. Given a url such as `http://example.org/example.html?auth[signature]=foo&auth[access_key_id]=KEY2` the following configuration will validate the signature with the secret `foo`:

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :hmac, :strategies => [:hmac_query, :hmac_header], 
                                     :store => false, 
							         :hmac => {
							           :secret => Proc.new {|strategy|
							             keys = {
							               "KEY1" => 'secrit',
							               "KEY2" => "foo"
							             }
               
							             access_key_id = strategy.params["auth"]["access_key_id"]
							             keys[access_key_id]
							           }
							         }
    end

To simplify the generation of such urls, the `HMAC::Signer` accepts an `:extra_auth_params` option for query based authentication. Parameters passed via this option will be injected in the auth hash. Parameters injected in the auth hash via this option will not be part of the signature, so only parameters that control the generation of the signature should be placed here.


    h.sign_url('http://example.org/example.html', 'foo', {:extra_auth_params => {"access_key_id" => "KEY2"}})


## Faraday Middleware

The library includes a faraday middleware that can be used to sign requests made with the faraday http lib. The middleware accepts the same list of options as the HMAC::Signer class.

### Example (query based)

    Faraday.new(:url => "http://example.com") do |builder|
      builder.use      Faraday::Request::Hmac, secret, {:query_based => true, :extra_auth_params => {"access_key_id" => "KEY2"}}
      builder.response :raise_error
      builder.adapter  :net_http
    end

### Example (header based with custom scheme name)

    Faraday.new(:url => "http://example.com") do |builder|
      builder.use      Faraday::Request::Hmac, secret, {:auth_scheme => 'MYSCHEME', :auth_key => 'TESTKEYID', :auth_header_format => '%{auth_scheme} %{auth_key} %{signature}'}}
      builder.response :raise_error
      builder.adapter  :net_http
    end

## Licence

Copyright (c) 2011 Florian Gilcher <florian.gilcher@asquera.de>, Felix Gilcher <felix.gilcher@asquera.de>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

