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
  
  def canonical_querystring(params)
    params.sort.map do |key, value|
      "%{key}=%{value}" % {:key   => CGI.escape(key), 
                           :value => CGI.escape(value)}
    end.join("&")
  end
  
end

