require 'addressable/uri'
require 'openssl'
require 'rack/utils'

class HMAC
  attr_accessor :secret, :algorithm, :default_opts

  # create a new HMAC instance
  #
  # @param [String] algorithm ('md5') The hashing-algorithm to use. See the openssl documentation for valid values.
  # @param [Hash] default_opts ({}) The default options for all calls that take opts
  #
  # @option default_opts [String]             :auth_param ('auth')   The name of the authentication param to use for query based authentication
  # @option default_opts [String]             :auth_header ('Authorization') The name of the authorization header to use
  # @option default_opts [String]             :auth_header_format ('%{auth_scheme} %{signature}') The format of the authorization header. Will be interpolated with the given options and the signature.
  # @option default_opts [String]             :nonce_header ('X-#{auth_scheme}-Nonce') The header name for the request nonce
  # @option default_opts [String]             :alternate_date_header ('X-#{auth_scheme}-Date') The header name for the alternate date header
  #
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
        "%{key}=%{value}" % {
          :key => Rack::Utils.unescape(key.to_s),
          :value => Rack::Utils.unescape(value.to_s)
        }
      end.join("&")
      rep << "?#{query}"
    end
    
    rep
  end
  
  # sign the given request
  #
  # @param [String] url     The url of the request
  # @param [String] secret  The shared secret for the signature
  # @param [Hash]   opts    Options for the signature generation
  #
  # @option opts [String]             :nonce ('')           The nonce to use in the signature
  # @option opts [String, #strftime]  :date (Time.now)      The date to use in the signature
  # @option opts [Hash]               :headers ({})         A list of optional headers to include in the signature
  # @option opts [Bool]               :query_based (false)  Includes the authentication data in the url instead of the headers
  # @option opts [String]             :use_alternate_date_header (false) Whether to use the alternate date header instead of 'Date'
  #                                   
  # @option opts [String]             :auth_param ('auth')   The name of the authentication param to use for query based authentication
  # @option opts [String]             :auth_header ('Authorization') The name of the authorization header to use
  # @option opts [String]             :auth_header_format ('%{auth_scheme} %{signature}') The format of the authorization header. Will be interpolated with the given options and the signature.
  # @option opts [String]             :nonce_header ('X-#{auth_scheme}-Nonce') The header name for the request nonce
  # @option opts [String]             :alternate_date_header ('X-#{auth_scheme}-Date') The header name for the alternate date header
  #
  def sign_request(url, secret, opts = {})
    opts = default_opts.merge(opts)
    
    uri = Addressable::URI.parse(url)
    headers = opts[:headers] || {}
    
    date = opts[:date] || Time.now.gmtime
    date = date.strftime('%a, %e %b %Y %T GMT') if date.respond_to? :strftime
    
    signature = generate_signature(:secret => secret, :method => "GET", :path => uri.path, :date => date, :nonce => opts[:nonce], :query => uri.query_values, :headers => opts[:headers])
      
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
  
end

