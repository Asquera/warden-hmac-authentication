require 'faraday'
require 'hmac/signer'

module Faraday
  class Request::Hmac < Faraday::Middleware
      
    # create a new Hmac middleware instance
    #
    # @param [Object] app           The url of the request
    # @param [String] secret        The shared secret for the signature
    # @param [Hash]   options       Options for the signature generation
    #
    # @option options [String]             :nonce ('')           The nonce to use in the signature
    # @option options [String, #strftime]  :date (Time.now)      The date to use in the signature
    # @option options [Hash]               :headers ({})         A list of optional headers to include in the signature
    #                       
    # @option options [String]             :auth_scheme ('HMAC')   The name of the authorization scheme used in the Authorization header and to construct various header-names
    # @option options [String]             :auth_param ('auth')   The name of the authentication param to use for query based authentication
    # @option options [Hash]               :extra_auth_params ({}) Additional parameters to inject in the auth parameter. This parameter is ignored unless :query_based evaluates to true.
    # @option options [String]             :auth_header ('Authorization') The name of the authorization header to use
    # @option options [String]             :auth_header_format ('%{auth_scheme} %{signature}') The format of the authorization header. Will be interpolated with the given options and the signature.
    # @option options [String]             :nonce_header ('X-#{auth_scheme}-Nonce') The header name for the request nonce
    # @option options [String]             :alternate_date_header ('X-#{auth_scheme}-Date') The header name for the alternate date header
    # @option options [Bool]               :query_based (false) Whether to use query based authentication
    # @option options [Bool]               :use_alternate_date_header (false) Use the alternate date header instead of `Date`
    #
    def initialize(app, secret, options = {})
      @app, @secret, @options, @query_values = app, secret, options
    end
  
    def call(env)
      sign(env)
      @app.call(env)
    end
  
    def sign(env)
      signer = HMAC::Signer.new
      url = env[:url]
      headers, url = *signer.sign_request(url, @secret, @options)
        
      env[:request_headers] = (env[:request_headers] || {}).merge(headers)
      env[:url] = Addressable::URI.parse(url)
      env
    end
      
  end
end