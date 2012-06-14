require 'hmac/signer'
require 'warden'


module Warden
  module Strategies
    module HMAC
      # Base class for hmac authentication in warden. Provides shared methods such as config access
      # and various helpers.
      #
      # @author Felix Gilcher <felix.gilcher@asquera.de>
      class Base < Warden::Strategies::Base
  

        # Performs authentication. Calls success! if authentication was performed successfully and halt!
        # if the authentication information is invalid.
        #
        # Delegates parts of the work to signature_valid? which must be implemented in child-strategies.
        #
        # @see https://github.com/hassox/warden/wiki/Strategies
        def authenticate!
          if "" == secret.to_s
            debug("authentication attempt with an empty secret")
            return fail!("Cannot authenticate with an empty secret")
          end
          
          if check_ttl? && !timestamp_valid?
            debug("authentication attempt with an invalid timestamp. Given was #{timestamp}, expected was #{Time.now.gmtime}")
            return fail!("Invalid timestamp")  
          end
    
          if signature_valid?
            success!(retrieve_user)
          else
            debug("authentication attempt with an invalid signature.")
            fail!("Invalid token passed")
          end
        end
  
        # Retrieve the current request method
        #
        # @return [String] The request method in capital letters
        def request_method
          env['REQUEST_METHOD'].upcase
        end
  
        # Retrieve the request query parameters
        #
        # @return [Hash] The query parameters
        def params
          request.GET
        end
  
        # Retrieve the request headers. Header names are normalized by this method by stripping
        # the `HTTP_`-prefix and replacing underscores with dashes. `HTTP_X_Foo` is normalized to
        # `X-Foo`.
        #
        # @return [Hash] The request headers
        def headers
          pairs = env.select {|k,v| k.start_with? 'HTTP_'}
              .collect {|pair| [pair[0].sub(/^HTTP_/, '').gsub(/_/, '-'), pair[1]]}
              .sort
           headers = Hash[*pairs.flatten]
           headers   
        end
  
        # Retrieve a user from the database. Calls the proc given in :retrieve_user, else returns true
        #
        # @return [Mixed] The result of the configured proc, true is no proc was given
        def retrieve_user
          @user ||= config[:retrieve_user].respond_to?(:call) ? config[:retrieve_user].call(self) : true
          @user
        end
  
        # Log a debug message if a logger is available.
        #
        # @param [String] msg The message to log
        def debug(msg)
          if logger
            logger.debug(msg)
          end
        end
  
        # Retrieve a logger. Current implementation can
        # only handle Padrino loggers
        #
        # @return [Logger] the logger, nil if none is available
        def logger
          if defined? Padrino
            Padrino.logger
          end
        end
  
        private
          def config
            if (env["warden"].config[:scope_defaults][scope] && env["warden"].config[:scope_defaults][scope][:hmac])
              env["warden"].config[:scope_defaults][scope][:hmac]
            else
              {}
            end
          end
    
          def auth_param
            config[:auth_param] || "auth"
          end
    
          def auth_header
            (config[:auth_header] || "Authorization").upcase
          end
    
          def auth_scheme_name
            config[:auth_scheme] || "HMAC"
          end
    
          def nonce_header_name
            (config[:nonce_header] || "X-#{auth_scheme_name}-Nonce").upcase
          end
    
          def alternate_date_header_name
            (config[:alternate_date_header] || "X-#{auth_scheme_name}-Date").upcase
          end

          def optional_headers
            ((config[:optional_headers] || []) + ["Content-MD5", "Content-Type"]).map {|h| h.upcase }
          end
          
          def auth_header_format
            config[:auth_header_format] || '%{scheme} %{signature}'
          end
          
          # check whether a nonce is set in the request
          #
          # @return [Bool] True if a nonce was given in the request
          def has_nonce?
            nonce && !nonce.to_s.empty?
          end
          
          def auth_header_parse
            unless @auth_header_parse
              r = config[:auth_header_parse]
              
              if !r
                # transforms the auth_header_format to a regular expression
                # that allows [-_+.\w] for each of the segments in the format string
                #
                # '%{scheme} %{signature}' => /(?<scheme>[-_+.\w]+) (?<signature>[-_+.\w]+)/
                #
                split_re = /(?<!%)(%{[^}]+})/
                replace_re = /(?<!%)%{([^}]+)}/
	  
          	    segments = auth_header_format.split split_re
                segments.each_index do |i; md, key|
                  md = replace_re.match(segments[i])
                  if ! md.nil?
                    key = md.captures[0].to_sym
                    segments[i] = "(?<#{key}>[-_+.\\w]+)"
                  else
                    segments[i] = segments[i].gsub "%%", "%"
                  end
                end
                r = Regexp.new segments.join
              end
              
              @auth_header_parse = r
            end
            
            @auth_header_parse
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
            ::HMAC::Signer.new(algorithm)
          end
    
          def algorithm
            config[:algorithm] || "sha1"
          end
    
          def ttl
            (config[:ttl] || 900).to_i
          end
    
          def check_ttl?
            !config.has_key?(:ttl) || !config[:ttl].nil?
          end

          def timestamp
            Time.strptime(request_timestamp, '%a, %e %b %Y %T %z') unless request_timestamp.nil? || request_timestamp.empty?
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
    end
  end
end