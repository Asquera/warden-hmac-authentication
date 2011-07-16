require_relative 'base'

class Warden::Strategies::HMACHeader < Warden::Strategies::HMACBase
  
  # Checks that this strategy applies. Tests that the required
  # authentication information was given.
  #
  # @return [Bool] true if all required authentication information is available in the request
  # @see https://github.com/hassox/warden/wiki/Strategies
  def valid?
    valid = required_headers.all? { |h| headers.include?(h) } && headers.include?("Authorization") && has_timestamp?
    valid = valid && scheme_valid?
    valid
  end

  def signature_valid?
    
    #:method => "GET",
    #:date => "Mon, 20 Jun 2011 12:06:11 GMT",
    #:nonce => "TESTNONCE",
    #:path => "/example",
    #:query => {
    #  "foo" => "bar",
    #  "baz" => "foobared"
    #},
    #:headers => {
    #  "Content-Type" => "application/json;charset=utf8",
    #  "Content-MD5" => "d41d8cd98f00b204e9800998ecf8427e"
    #}
    
    hmac.check_signature(given_signature, {
      :secret => secret,
      :method => request_method,
      :date => request_timestamp,
      :nonce => nonce,
      :path => request.path,
      :query => params,
      :headers => headers.select {|name, value| optional_headers.include? name}
    })
  end
  
  def given_signature
    headers[auth_header].split(" ")[1]
  end
  
  def request_timestamp
    headers[date_header]
  end
  
  def nonce
    headers[nonce_header_name]
  end
  
  private
    
    def required_headers
      headers = [auth_header]
      headers += [nonce_header_name] if nonce_required? 
      headers
    end

    def auth_scheme_name
      config[:auth_scheme] || "HMAC"
    end
    
    def scheme_valid?
      headers[auth_header].to_s.split(" ").first == auth_scheme_name
    end
    
    def nonce_header_name
      config[:nonce_header] || "X-#{auth_scheme_name}-Nonce"
    end
    
    def alternate_date_header_name
      config[:alternate_date_header] || "X-#{auth_scheme_name}-Date"
    end

    def date_header
      if headers.include? alternate_date_header_name
        alternate_date_header_name
      else
        "Date"
      end
    end
    
    def auth_header
      config[:auth_header] || "Authorization"
    end

    def auth_param
      config[:auth_param] || "auth"
    end
      
end

Warden::Strategies.add(:hmac_header, Warden::Strategies::HMACHeader)
