require_relative 'base'

module Warden
  module Strategies
    module HMAC
      # Implements query-based hmac authentication for warden. The strategy is registered as
      # `:hmac_query` in the warden strategy list.
      #
      # @author Felix Gilcher <felix.gilcher@asquera.de>
      class Warden::Strategies::HMAC::Query < Warden::Strategies::HMAC::Base
  
        # Checks that this strategy applies. Tests that the required
        # authentication information was given.
        #
        # @return [Bool] true if all required authentication information is available in the request
        # @see https://github.com/hassox/warden/wiki/Strategies
        def valid?
          valid = has_signature?
          valid = valid && has_timestamp? if check_ttl?
          valid = valid && has_nonce? if nonce_required?
          valid
        end
        
        # Checks that the request contains a signature
        #
        # @return [Bool] true if the request contains a signature
        def has_signature?
          auth_info.include? "signature"
        end
        
        # Check that the signature given in the request is valid.
        #
        # @return [Bool] true if the request is valid
        def signature_valid?
          hmac.validate_url_signature(request.url, secret)
        end
  
        # retrieve the authentication information from the request
        #
        # @return [Hash] the authentication info in the request
        def auth_info
          params[auth_param] || {}
        end
  
        # retrieve the nonce from the request
        #
        # @return [String] The nonce or an empty string if no nonce was given in the request
        def nonce
          auth_info["nonce"] || ""
        end
  
        # retrieve the request timestamp as string
        #
        # @return [String] The request timestamp or an empty string if no timestamp was given in the request
        def request_timestamp
          auth_info["date"] || ""
        end
      
      end
    end
  end
end

Warden::Strategies.add(:hmac_query, Warden::Strategies::HMAC::Query)
