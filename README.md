# HMAC

This gem provides request authentication via HMAC. Two strategies are supported that differ mainly in how the authentication information
is transmitted to the server: One header-based authentication method and one query-based.

The gem also provides a small helper class that can be used to generate request signatures.

## Auth Scheme Name

The name of the auth scheme is primarily used for header authentication. It is used to construct the `Authorization` header and 
must thus avoid names that are reserved for existing standardized authentication schemes such as `Basic` and `Digest`. The scheme
name is also used to construct the default values for various header names.

## Shared secret

Both strategies use a secret that is shared between the server and the client to calculate the signature. The secret must be
configured when registering the strategy. For simple cases a single secret may be sufficient but most real-world scenarios
will require a different secret for each possible client. Such cases can be managed by passing a callable object (a proc for example)
as secret. The proc get passed the strategy object and thus has full access to all request parameters and header. It should return
a string. If the proc returns nil or an empty string authentication fails.

## Optional nonce

An optional nonce can be passed in the request to increase security. The nonce is not limited to digits and can be any string. It's
advisable to limit the length of the nonce to a reasonable value. If a nonce is used it should be changed with every request. The
default header for the nonce is `X-#{auth-scheme-name}-Nonce`. The header name can be controlled using the `:nonce_header` 
configuration option.

The `:require_nonce` configuration can be set to `true` to enforce a nonce. If a nonce is required no authentication attempt will be
made for requests not providing a nonce.

## Required headers and parameters

Required headers and parameters must be present for a successful authentication attempt. The list of required headers defaults to 
the `Authorization` header for header-based authentication and is empty for query-based authentication. The list of required
parameters defaults to the chosen authentication parameter for query-based auth and is empty for header-based auth. If a required
parameter or header is not included in the request, no authentication attempt will be made for the strategy.

Additional required headers and parameters can be defined using the `:required_headers` and `:required_parameters` config options.
Keep in mind that additional required parameters will be required for header-based authentication as well as additional required
headers will be required for query-based authentication.

## Other optional headers

Some headers are optional but should be included in the signature of the request if present. The default list of optional headers
includes `Content-MD5` and `Content-Type`. The list of optional headers can be configured using the `:optional_headers` config option.
Optional headers are always included in the canonical representation if they are found in the request and not blank. Optional headers
will be included in the canonical representation for query-based auth if they are present in the request so be careful not to include
any header that is out of your clients control.

## Date and TTL

It is good practice to enforce a max-age for tokens. The hmac strategy allows this via the `ttl` parameter. It controls the max age 
of tokens in seconds and defaults to 900 seconds. Pass `nil` as ttl value to disable TTL checking.

The timestamp of the request is usually passed in the `Date` HTTP-Header. However, since some HTTP-Client libraries do not allow 
setting the Date header another header may be used to override the `Date` header. The name of this header can be controlled via the
`:alternate_date_header` option and defaults to `X-#{auth-scheme-name}-Date`. 

The date must be formatted as HTTP-Date according to RFC 1123, section 5.2.14 and should be provided in GMT time.

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :token, :strategies => [:hmac_header], 
                                     :store => false, 
                                     :hmac => { 
                                       :secret => "secrit",
                                       :algorithm => "md5",
                                       :ttl => 300, # make tokens valid for 5 minutes
                                       :timestamp => "generated_at", # the information when the token was generated is found in the request parameter named "generated_at"
                                       :hmac => HMAC
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
* Append the query string using a single question mark (“?”) as separator

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


## Header-Based authentication

The header-based authentication transports the authentication information in the (misnamed) `Authorization` HTTP-Header. The primary 
advantage of header-based authentication is that request urls are stable even if authentication information changes. The improves
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

### Generating the canonical representation for query-based authentication

The canonical representation for query-based authentication is generated using the same algorithm as for header-based auth, but some
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


## HMAC usage

The HMAC class can be used to validate and generate signatures for a given request.

    h = HMAC.new('md5')
    h.generate_signature(canonical_representation, 'secret')
    
    h.validated_signature(canonical_representation, signature, 'secret')


    
    
## Warden strategy usage

Configure the HMAC warden strategy:

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :token, :strategies => [:hmac], 
                                     :store => false, 
                                     :hmac => { 
                                       :params => ["user_id"],
                                       :token => "token",
                                       :secret => "secrit",
                                       :algorithm => "md5",
                                       :hmac => HMAC
                                     }
    end

`params` allows you to specify parameters the request must contain, `token` is the name of the token parameter, `secret` and `algorithm` allow you to specify
the secret and algorithm used for the HMAC algorithm. `hmac` expects a class that implements the HMAC algorithm. It is instantiated on each request.

If you want to retrieve the secret and token using a different strategy, extend the HMAC strategy:

    class Warden::Strategies::HMAC < Warden::Strategies::Base
      def retrieve_user
        User.get(request[:user_id])
      end
      
      def secret
        retrieve_user.secret
      end
    end

The configured secret may also be a proc that retrieves a given secret. The proc must return a string in all cases. The strategy itself is passed as the only parameter
to the given proc and allows access to the full rack env.


    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :token, :strategies => [:hmac], 
                                     :store => false, 
                                     :hmac => { 
                                       :params => ["user_id"],
                                       :token => "token",
                                       :secret => Proc.new {|strategy|
                                         "secret"
                                       },
                                       :algorithm => "md5",
                                       :hmac => HMAC
                                     }
    end
    
### Controlling TTLs

It is good practice to enforce a max-age for tokens. The hmac strategy allows this by adding two parameters: `ttl` and `timestamp`. The `ttl` parameter controls the max age
of tokens in seconds. `timestamp` is the name of the request parameter containing a timestamp (in microseconds UTC) when the token was generated. `timestamp` defaults to "timestamp" if not given.

    use Warden::Manager do |manager|
      manager.failure_app = -> env { [401, {"Content-Length" => "0"}, [""]] }
      # other scopes
      manager.scope_defaults :token, :strategies => [:hmac], 
                                     :store => false, 
                                     :hmac => { 
                                       :params => ["user_id"],
                                       :token => "token",
                                       :secret => "secrit",
                                       :algorithm => "md5",
                                       :ttl => 300, # make tokens valid for 5 minutes
                                       :timestamp => "generated_at", # the information when the token was generated is found in the request parameter named "generated_at"
                                       :hmac => HMAC
                                     }
    end

The TTL allows for a little clock skew to accommodate servers that are slightly running off time. The allowed clock skew can be controlled with the `:clockskew` option and defaults to 5 seconds. Thus 
timestamps that are 5 seconds into the future relative to the servers time are considered valid. The skew must be 0 or bigger.