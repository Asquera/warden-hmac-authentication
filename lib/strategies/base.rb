require 'hmac'
require 'warden'

class Warden::Strategies::HMACBase < Warden::Strategies::Base
  
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
  
  def debug(msg)
    if logger
      logger.debug(msg)
    end
  end
  
  def logger
    if defined? Padrino
      Padrino.logger
    end
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
    
    def ttl
      config[:ttl].to_i
    end
    
    def check_ttl?
      !config[:ttl].nil?
    end

    def timestamp
      Time.strptime(request_timestamp, '%a, %e %b %Y %T %z') unless request_timestamp.nil?
    end
    
    def has_timestamp?
      !timestamp.nil?
    end
    
    def timestamp_valid?
      now = Time.now.gmtime.to_i
      timestamp.to_i <= (now + clockskew) && timestamp.to_i >= (now - ttl)
    end
    
    def nonce_required?
      !!config[:require_nonce]
    end
    
    def secret
      @secret ||= config[:secret].respond_to?(:call) ? config[:secret].call(self) : config[:secret]
    end
    
    def clockskew
      (config[:clockskew] || 5)
    end
    
    
end