require 'addressable/uri'
require 'openssl'
require 'rack/utils'
if defined?(JRUBY_VERSION) && RUBY_VERSION =~ /^1\.9/
  require 'hmac/string/jruby'
end

module HMAC
  # Helper class that provides signing capabilites for the hmac strategies.
  #
  # @author Felix Gilcher <felix.gilcher@asquera.de>
  class Signer
    attr_accessor :secret, :algorithm, :default_opts

    # create a new HMAC instance
    #
    # @param [String] algorithm   The hashing-algorithm to use. See the openssl documentation for valid values.
    # @param [Hash] default_opts  The default options for all calls that take opts
    #
    # @option default_opts [String]             :auth_scheme ('HMAC')   The name of the authorization scheme used in the Authorization header and to construct various header-names
    # @option default_opts [String]             :auth_param ('auth')   The name of the authentication param to use for query based authentication
    # @option default_opts [String]             :auth_header ('Authorization') The name of the authorization header to use
    # @option default_opts [String]             :auth_header_format ('%{auth_scheme} %{signature}') The format of the authorization header. Will be interpolated with the given options and the signature.
    # @option default_opts [String]             :nonce_header ('X-#{auth_scheme}-Nonce') The header name for the request nonce
    # @option default_opts [String]             :alternate_date_header ('X-#{auth_scheme}-Date') The header name for the alternate date header
    # @option default_opts [Bool]               :query_based (false) Whether to use query based authentication
    # @option default_opts [Bool]               :use_alternate_date_header (false) Use the alternate date header instead of `Date`
    #
    def initialize(algorithm = "sha1", default_opts = {})
      self.algorithm = algorithm
      self.default_opts = {
        :auth_scheme => "HMAC",
        :auth_param => "auth",
        :auth_header => "Authorization",
        :auth_header_format => "%{auth_scheme} %{signature}",
        :nonce_header => "X-%{scheme}-Nonce" % {:scheme => (default_opts[:auth_scheme] || "HMAC")},
        :alternate_date_header => "X-%{scheme}-Date" % {:scheme => (default_opts[:auth_scheme] || "HMAC")},
        :query_based => false,
        :use_alternate_date_header => false
      }.merge(default_opts)
    
    end
  
    # Generate the signature from a hash representation
    # 
    # returns nil if no secret or an empty secret was given
    #
    # @param [Hash] params the parameters to create the representation with
    # @option params [String] :secret The secret to generate the signature with
    # @option params [String] :method The HTTP Verb of the request
    # @option params [String] :date The date of the request as it was formatted in the request
    # @option params [String] :nonce ('') The nonce given in the request
    # @option params [String] :path The path portion of the request
    # @option params [Hash]   :query ({}) The query parameters given in the request. Must not contain the auth param.
    # @option params [Hash]   :headers ({}) All headers given in the request (optional and required)
    # @option params [String]             :auth_scheme ('HMAC')   The name of the authorization scheme used in the Authorization header and to construct various header-names
    # @option params [String]             :auth_param ('auth')   The name of the authentication param to use for query based authentication
    # @option params [String]             :auth_header ('Authorization') The name of the authorization header to use
    # @option params [String]             :auth_header_format ('%{auth_scheme} %{signature}') The format of the authorization header. Will be interpolated with the given options and the signature.
    # @option params [String]             :nonce_header ('X-#{auth_scheme}-Nonce') The header name for the request nonce
    # @option params [String]             :alternate_date_header ('X-#{auth_scheme}-Date') The header name for the alternate date header
    # @option params [Bool]               :query_based (false) Whether to use query based authentication
    # @option params [Bool]               :use_alternate_date_header (false) Use the alternate date header instead of `Date`
    #
    # @return [String] the signature
    def generate_signature(params)
      secret = params.delete(:secret)
      
      # jruby stumbles over empty secrets, we regard them as invalid anyways, so we return an empty digest if no scret was given
      if '' == secret.to_s
        nil
      else
        OpenSSL::HMAC.hexdigest(algorithm, secret, canonical_representation(params))
      end
    end
  
    # compares the given signature with the signature created from a hash representation
    #
    # @param [String] signature the signature to compare with
    # @param [Hash] params the parameters to create the representation with
    # @option params [String] :secret The secret to generate the signature with
    # @option params [String] :method The HTTP Verb of the request
    # @option params [String] :date The date of the request as it was formatted in the request
    # @option params [String] :nonce ('') The nonce given in the request
    # @option params [String] :path The path portion of the request
    # @option params [Hash]   :query ({}) The query parameters given in the request. Must not contain the auth param.
    # @option params [Hash]   :headers ({}) All headers given in the request (optional and required)
    # @option params [String]             :auth_scheme ('HMAC')   The name of the authorization scheme used in the Authorization header and to construct various header-names
    # @option params [String]             :auth_param ('auth')   The name of the authentication param to use for query based authentication
    # @option params [String]             :auth_header ('Authorization') The name of the authorization header to use
    # @option params [String]             :auth_header_format ('%{auth_scheme} %{signature}') The format of the authorization header. Will be interpolated with the given options and the signature.
    # @option params [String]             :nonce_header ('X-#{auth_scheme}-Nonce') The header name for the request nonce
    # @option params [String]             :alternate_date_header ('X-#{auth_scheme}-Date') The header name for the alternate date header
    # @option params [Bool]               :query_based (false) Whether to use query based authentication
    # @option params [Bool]               :use_alternate_date_header (false) Use the alternate date header instead of `Date`
    #
    # @return [Bool] true if the signature matches
    def validate_signature(signature, params)
      signature == generate_signature(params)
    end
  
    # convienience method to check the signature of a url with query-based authentication
    #
    # @param [String] url the url to test
    # @param [String] secret the secret used to sign the url
    # @param [Hash] opts Options controlling the singature generation
    #
    # @option opts [String]             :auth_param ('auth')   The name of the authentication param to use for query based authentication
    #
    # @return [Bool] true if the signature is valid
    def validate_url_signature(url, secret, opts = {})
      opts = default_opts.merge(opts)
      opts[:query_based] = true
    
      uri = Addressable::URI.parse(url)
      query_values = uri.query_values
      auth_params = query_values.delete(opts[:auth_param])
    
      date = auth_params["date"]
      nonce = auth_params["nonce"]
      validate_signature(auth_params["signature"], :secret => secret, :method => "GET", :path => uri.path, :date => date, :nonce => nonce, :query => query_values, :headers => {})
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
    # @option params [String] :auth_scheme ('HMAC')   The name of the authorization scheme used in the Authorization header and to construct various header-names
    # @option params [String] :auth_param ('auth')   The name of the authentication param to use for query based authentication
    # @option params [String] :auth_header ('Authorization') The name of the authorization header to use
    # @option params [String] :auth_header_format ('%{auth_scheme} %{signature}') The format of the authorization header. Will be interpolated with the given options and the signature.
    # @option params [String] :nonce_header ('X-#{auth_scheme}-Nonce') The header name for the request nonce
    # @option params [String] :alternate_date_header ('X-#{auth_scheme}-Date') The header name for the alternate date header
    # @option params [Bool]   :query_based (false) Whether to use query based authentication
    # @option params [Bool]   :use_alternate_date_header (false) Use the alternate date header instead of `Date`
    #
    # @return [String] the canonical representation
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
    #                                   
    # @option opts [String]             :auth_scheme ('HMAC')   The name of the authorization scheme used in the Authorization header and to construct various header-names
    # @option opts [String]             :auth_param ('auth')   The name of the authentication param to use for query based authentication
    # @option opts [String]             :auth_header ('Authorization') The name of the authorization header to use
    # @option opts [String]             :auth_header_format ('%{auth_scheme} %{signature}') The format of the authorization header. Will be interpolated with the given options and the signature.
    # @option opts [String]             :nonce_header ('X-#{auth_scheme}-Nonce') The header name for the request nonce
    # @option opts [String]             :alternate_date_header ('X-#{auth_scheme}-Date') The header name for the alternate date header
    # @option opts [Bool]               :query_based (false) Whether to use query based authentication
    # @option opts [Bool]               :use_alternate_date_header (false) Use the alternate date header instead of `Date`
    #
    def sign_request(url, secret, opts = {})
      opts = default_opts.merge(opts)
    
      uri = Addressable::URI.parse(url)
      headers = opts[:headers] || {}
    
      date = opts[:date] || Time.now.gmtime
      date = date.gmtime.strftime('%a, %e %b %Y %T GMT') if date.respond_to? :strftime
    
      signature = generate_signature(:secret => secret, :method => "GET", :path => uri.path, :date => date, :nonce => opts[:nonce], :query => uri.query_values, :headers => opts[:headers])
      
      if opts[:query_based]
        auth_params = {
          "date" => date,
          "signature" => signature
        }
        auth_params[:nonce] = opts[:nonce] unless opts[:nonce].nil?
      
        query_values =  uri.query_values || {}
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
  
    # convienience method to sign a url for use with query-based authentication
    #
    # @param [String] url the url to sign
    # @param [String] secret the secret used to sign the url
    # @param [Hash] opts Options controlling the singature generation
    #
    # @option opts [String] :auth_param ('auth')   The name of the authentication param to use for query based authentication
    #
    # @return [String] The signed url
    def sign_url(url, secret, opts = {})
      opts = default_opts.merge(opts)
      opts[:query_based] = true
    
      headers, url = *sign_request(url, secret, opts)
      url  
    end
  
  
  end
end
