require 'cgi'
require 'addressable/uri'
require 'openssl'
require 'rack/utils'

class HMAC
  attr_accessor :secret, :algorithm, :default_opts

  def initialize(algorithm = "md5", default_opts = {})
    self.algorithm = algorithm
    self.default_opts = {
      :auth_scheme => "HMAC",
      :alternate_date_header => "X-%{scheme}-Date" % {:scheme => (default_opts[:auth_scheme] || "HMAC")},
      :nonce_header => "X-%{scheme}-Nonce" % {:scheme => (default_opts[:auth_scheme] || "HMAC")},
      :query_based => false,
      :use_alternate_date_header => false,
      :auth_param => "auth",
      :auth_header => "Authorization",
      :auth_header_format => "%{auth_scheme} %{signature}"
    }.merge(default_opts)
    
  end
  
  def generate_signature(params)
    secret = params.delete(:secret)
    OpenSSL::HMAC.hexdigest(algorithm, secret, canonical_representation(params))
  end
  
  def check_signature(signature, params)
    signature == generate_signature(params)
  end

  # generates the canonical representation for a given request
  # 
  # @param [Hash] params the parameters to create the representation with
  # @option params [String] :method The HTTP Verb of the request
  # @option params [String] :date The date of the request as it was formatted in the request
  # @option params [String] :nonce ('') The nonce given in the request
  # @option params [String] :path The path portion of the request
  # @option params [Hash]   :query ({}) The query parameters given in the request. Must not contain the auth param.
  # @option params [Hash]   :headers ({}) All headers given in the request (optional and required)
  #
  def canonical_representation(params)
    rep = ""
    
    rep << "#{params[:method].upcase}\n" 
    rep << "date:#{params[:date]}\n"
    rep << "nonce:#{params[:nonce]}\n"
    
    (params[:headers] || {}).sort.each do |pair|
      name,value = *pair
      rep << "#{name.downcase}:#{value}\n"
    end
    
    rep << params[:path]
    
    p = (params[:query] || {}).dup
    
    if !p.empty?
      query = p.sort.map do |key, value|
        "%{key}=%{value}" % {:key => Rack::Utils.unescape(key.to_s), :value => Rack::Utils.unescape(value.to_s)}
      end.join("&")
      rep << "?#{query}"
    end
    
    rep
  end
  
  def sign_request(url, secret, opts = {})
    opts = default_opts.merge(opts)
    
    uri = Addressable::URI.parse(url)
    headers = {}
    
    date = opts[:date] || Time.now.gmtime
    date = date.strftime('%a, %e %b %Y %T GMT') if date.respond_to? :strftime
    
    signature = generate_signature(:secret => secret, :method => "GET", :path => uri.path, :date => date, :nonce => opts[:nonce], :query => uri.query_values, :headers => {})
    #signature = generate_signature(rep, secret)
      
    if opts[:query_based]
      auth_params = {
        "date" => date,
        "signature" => signature
      }
      auth_params[:nonce] = opts[:nonce] unless opts[:nonce].nil?
      
      query_values =  uri.query_values
      query_values[opts[:auth_param]] = auth_params
      uri.query_values = query_values
    else
      headers[opts[:auth_header]]   = opts[:auth_header_format] % opts.merge({:signature => signature})
      headers[opts[:nonce_header]]  = opts[:nonce] unless opts[:nonce].nil?
      
      if opts[:use_alternate_date_header] 
        headers[opts[:alternate_date_header]] = date
      else
        headers["Date"] = date
      end
    end
    
    [headers, uri.to_s]
  end
  
  def sign_url(url, secret, opts = {})
    opts = default_opts.merge(opts)
    opts[:query_based] = true
    
    headers, url = *sign_request(url, secret, opts)
    url  
  end
  
  def check_url_signature(url, secret, opts = {})
    opts = default_opts.merge(opts)
    opts[:query_based] = true
    
    uri = Addressable::URI.parse(url)
    query_values = uri.query_values
    auth_params = query_values.delete(opts[:auth_param])
    
    date = auth_params["date"]
    nonce = auth_params["nonce"]
    check_signature(auth_params["signature"], :secret => secret, :method => "GET", :path => uri.path, :date => date, :nonce => nonce, :query => query_values, :headers => {})
  end
  
  def canonical_querystring(params)
    params.sort.map do |key, value|
      "%{key}=%{value}" % {:key   => Rack::Utils.unescape(key.to_s), 
                           :value => Rack::Utils.unescape(value.to_s)}
    end.join("&")
  end
  
end

