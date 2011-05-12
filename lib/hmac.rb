require 'cgi'
require 'addressable/uri'
require 'openssl'

class HMAC
  attr_accessor :secret, :algorithm

  def initialize(algorithm = "md5")
    self.secret    = secret
    self.algorithm = algorithm
  end
  
  def generate_signature(url, secret, token = "token")
    uri          = Addressable::URI.parse(url)
    query_values = uri.query_values

    return false unless query_values

    query_values.delete(token)
    uri.query    = canonical_querystring(query_values)
    
    OpenSSL::HMAC.hexdigest(algorithm, secret, uri.to_s)
  end
  
  def check_signature(url, secret, token = "token")
    query_values = Addressable::URI.parse(url).query_values

    return false unless query_values

    query_values[token] == generate_signature(url, secret, token)
  end
  
  def sign_url(url, secret, token = "token", extra_params = {})
    uri          = Addressable::URI.parse(url)
    
    query_values = (uri.query_values || {}).merge(extra_params)
    uri.query_values = query_values
    
    signature = generate_signature(uri.to_s, secret, token)
    
    uri.query_values = query_values.merge({token => signature})
    uri.to_s
  end
  
  def canonical_querystring(params)
    params.sort.map do |key, value|
      "%{key}=%{value}" % {:key   => CGI.escape(key.to_s), 
                           :value => CGI.escape(value.to_s)}
    end.join("&")
  end
  
end

