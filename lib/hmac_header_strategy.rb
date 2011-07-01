require 'hmac'
require 'warden'
require 'cgi'

class Warden::Strategies::HMACHeader < Warden::Strategies::Base
  
  def valid?
    required_headers.all? { |h| headers.include?(h) } && headers.include? "Authorization" && has_timestamp?
  end

  def authenticate!
    if "" == secret.to_s
      return fail!("Cannot authenticate with an empty secret")
    end
    
    if check_ttl? && !timestamp_valid?
      return fail!("Invalid timestamp")  
    end
    
    if hmac.check_signature(request.url, secret, token)
      success!(retrieve_user)
    else
      fail!("Invalid token passed")
    end
  end
  
  def params
    request.GET
  end
  
  def headers
    request.headers
  end

  def canonical_representation
    rep = ""
    rep << "#{request.method}\n" 
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
        Hash[*tmp.flatten]
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
      config[:auth_scheme] || "MAC"
    end
    
    def nonce_header_name
      config[:nonce_header] || "X-#{auth_scheme_name}-Nonce"
    end
    
    def alternate_date_header_name
      config[:alternate_date_header] || "X-#{auth_scheme_name}-Date"
    end

    def date_header
      if headers.include? timestamp_name
        timestamp_name
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
      DateTime.strptime(headers[date_header], '%a, %e %b %Y %T %z') if headers.include? date_header
    end
    
    def timestamp_valid?
      now = (Time.now.gmtime.to_f * 1000).round
      timestamp < (now + clockskew) && timestamp > (now - ttl * 1000)
    end
    
    def nonce
      headers[nonce_header_name]
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
      config[:algorithm]
    end
    
end

Warden::Strategies.add(:hmac_header, Warden::Strategies::HMACHeader)
