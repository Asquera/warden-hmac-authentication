require 'hmac'
require 'warden'

class Warden::Strategies::HMAC < Warden::Strategies::Base
  def valid?
    #valid = config[:params].all? { |p| params.include?(p.to_s) } && params.include?(token)
    valid = valid && params.include?(timestamp_name) if check_ttl?  
    valid
  end

  def authenticate!
    if "" == secret.to_s
      return fail!("Cannot authenticate with an empty secret")
    end
    
    if check_ttl? && !timestamp_valid?
      return fail!("Invalid timestamp")  
    end
    
    if hmac.check_url_signature(request.url, secret)
      success!(retrieve_user)
    else
      fail!("Invalid token passed")
    end
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
  
  
  def auth_info
    params[auth_param] || {}
  end
  
  def signature
    auth_info["hmac"]
  end
  
  def nonce
    auth_info["nonce"] || ""
  end
  
  def request_timestamp
    auth_info["date"] || ""
  end
  
  def request_method
    env['REQUEST_METHOD'].upcase
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
  
  def retrieve_user
    true
  end
  
  private
    def config
      env["warden"].config[:scope_defaults][scope][:hmac]
    end
    
    def auth_param
      config[:auth_param] || "auth"
    end
    
    def optional_headers
      (config[:optional_headers] || []) + ["Content-MD5", "Content-Type"]
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
    
    def hmac
      HMAC.new(algorithm)
    end
    
    def algorithm
      config[:algorithm] || "sha1"
    end
    
    def token
      config[:token]
    end
    
    def ttl
      config[:ttl].to_i
    end
    
    def check_ttl?
      !config[:ttl].nil?
    end

    def timestamp_name
      config[:timestamp] || "timestamp"
    end

    def timestamp
      params[timestamp_name].to_i
    end
    
    def timestamp_valid?
      now = (Time.now.gmtime.to_f * 1000).round
      timestamp < (now + clockskew) && timestamp > (now - ttl * 1000)
    end

    def secret
      @secret ||= config[:secret].respond_to?(:call) ? config[:secret].call(self) : config[:secret]
    end
    
    def clockskew
      (config[:clockskew] || 5) * 1000
    end
end

Warden::Strategies.add(:hmac, Warden::Strategies::HMAC)
