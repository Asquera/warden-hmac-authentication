begin
  # Require the preresolved locked set of gems.
  require File.expand_path('../../.bundle/environment', __FILE__)
rescue LoadError
  # Fallback on doing the resolve at runtime.
  require 'rubygems'
  require 'bundler'
  Bundler.setup
end

Bundler.require(:default, :test)

require 'rack/test'
require 'riot'
require 'warden'
require 'timecop'

begin
  require 'simplecov'
  require 'simplecov-html'

  SimpleCov.start 
rescue LoadError => e
  # swallow, code coverage is only supported on mri
end

class Riot::Situation
  include Rack::Test::Methods
  include Warden::Test::Helpers


  FAILURE_APP = lambda{|e|[401, {"Content-Type" => "text/plain"}, ["You Fail!"]] }

  def env_with_params(path = "/", params = {}, env = {})
    method = params.delete(:method) || "GET"
    env = { 'HTTP_VERSION' => '1.1', 'REQUEST_METHOD' => "#{method}" }.merge(env)
    Rack::MockRequest.env_for("#{path}?#{Rack::Utils.build_query(params)}", env)
  end

  def setup_rack(app = nil, opts = {}, &block)
    app ||= block if block_given?

    opts[:failure_app]         ||= failure_app
    opts[:default_strategies]  ||= [:password]
    opts[:default_serializers] ||= [:session]

    Rack::Builder.new do
      use opts[:session] || Warden::Spec::Helpers::Session
      use Warden::Manager, opts
      run app
    end
  end

  def valid_response
    Rack::Response.new("OK").finish
  end

  def failure_app
    Warden::Spec::Helpers::FAILURE_APP
  end

  def success_app
    lambda{|e| [200, {"Content-Type" => "text/plain"}, ["You Win"]]}
  end

  class Session
    attr_accessor :app
    def initialize(app,configs = {})
      @app = app
    end

    def call(e)
      e['rack.session'] ||= {}
      @app.call(e)
    end
  end # session
    
  def app
    @app
  end
end

class Riot::Context
  # Set the Rack app which is to be tested.
  #
  #   context "MyApp" do
  #     app { [200, {}, "Hello!"] }
  #     setup { get '/' }
  #     asserts(:status).equals(200)
  #   end
  def app(app=nil, &block)
    setup { @app = (app || block) }
  end
end
