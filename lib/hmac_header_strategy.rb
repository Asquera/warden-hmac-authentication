require 'hmac'
require 'warden'
require 'cgi'

class Warden::Strategies::HMACHeader < Warden::Strategies::Base
  
  def valid?
    valid = required_headers.all? { |h| headers.include?(h) } && headers.include?("Authorization") && has_timestamp?
    valid = valid && scheme_valid?
    valid
  end

  def authenticate!
    if "" == secret.to_s
      return fail!("Cannot authenticate with an empty secret")
    end
    
    if check_ttl? && !timestamp_valid?
      return fail!("Invalid timestamp")  
    end
    
    if hmac.check_signature(canonical_representation, secret, signature)
      success!(retrieve_user)
    else
      fail!("Invalid token passed")
    end
  end
  
  def signature
    headers[auth_header].split(" ")[1]
  end
  
  def params
    request.GET
  end
  
  def headers
    pairs = env.select {|k,v| k.start_with? 'HTTP_'}
        .collect {|pair| [pair[0].sub(/^HTTP_/, '').gsub(/_/, '-'), pair[1]]}
        .sort
     headers = Hash[*pairs.flatten]
     headers   
  end
  
  def request_method
    env['REQUEST_METHOD'].upcase
  end

  def canonical_representation
    rep = ""
    
    rep << "#{request_method}\n" 
    rep << "date:#{request_timestamp}\n"
    rep << "nonce:#{nonce}\n"
    
    optional_headers.map {|header_name| header_name.downcase}.sort.each do |header_name|
      rep << "#{header_name}:#{lowercase_headers[header_name]}\n" unless lowercase_headers[header_name].nil?
    end
    
    rep << request.path
    
    p = params.dup
    p.delete auth_param
    
    if !p.empty?
      query = p.sort.map do |key, value|
        "%{key}=%{value}"
      end.join("&")
      rep << "?#{query}"
    end
    
    rep
  end
  
  def retrieve_user
    true
  end
  
  private
    
    
    def config
      env["warden"].config[:scope_defaults][scope][:hmac]
    end
    
    def lowercase_headers

      if @lowercase_headers.nil?
        tmp = headers.map do |name,value|
          [name.downcase, value]
        end
        @lowercase_headers = Hash[*tmp.flatten]
      end

      @lowercase_headers
    end
    
    def required_headers
      headers = [auth_header]
      headers += [nonce_header_name] if nonce_required? 
      headers
    end

    def optional_headers
      (config[:optional_headers] || []) + ["Content-MD5", "Content-Type"]
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

    def has_timestamp?
      headers.include? date_header
    end
    
    def ttl
      if config.include? :ttl
        config[:ttl].to_i unless config[:ttl].nil?
      else
        900
      end
    end
    
    def check_ttl?
      !ttl.nil?
    end

    def request_timestamp
      headers[date_header]
    end

    def timestamp
      Time.strptime(headers[date_header], '%a, %e %b %Y %T %z') if headers.include? date_header
    end
    
    def timestamp_valid?
      now = Time.now.gmtime.to_i
      timestamp.to_i < (now + clockskew) && timestamp.to_i > (now - ttl)
    end
    
    def nonce
      headers[nonce_header_name]
    end

    def nonce_required?
      !!config[:require_nonce]
    end

    def secret
      @secret ||= config[:secret].respond_to?(:call) ? config[:secret].call(self) : config[:secret]
    end
    
    def clockskew
      config[:clockskew] || 5
    end
    
    def hmac
      HMAC.new(algorithm)
    end

    def algorithm
      config[:algorithm] || "sha1"
    end
    
end

Warden::Strategies.add(:hmac_header, Warden::Strategies::HMACHeader)
