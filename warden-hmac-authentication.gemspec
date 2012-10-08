# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name        = "warden-hmac-authentication"
  s.version     = "0.6.2"
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Felix Gilcher", "Florian Gilcher"]
  s.email       = ["felix.gilcher@asquera.de", "florian.gilcher@asquera.de"]
  s.homepage    = "https://github.com/Asquera/warden-hmac-authentication"
  s.summary     = %q{Provides request based, non-interactive authentication for APIs}
  s.description = %q{This gem provides request authentication via [HMAC](http://en.wikipedia.org/wiki/Hmac). The main usage is request based, noninteractive
  authentication for API implementations. Two strategies are supported that differ mainly in how the authentication information is
  transferred to the server: One header-based authentication method and one query-based. The authentication scheme is in some parts based
  on ideas laid out in this article and the following discussion: 
  http://broadcast.oreilly.com/2009/12/principles-for-standardized-rest-authentication.html

  The gem also provides a small helper class that can be used to generate request signatures.}
  
  s.files = %w( README.md Rakefile LICENSE )
  s.files += Dir.glob("lib/**/*")
  
  s.require_paths = ["lib"]
  
  s.executables   = ["warden-hmac-authentication"]
  
  s.add_runtime_dependency(%q<rack>)
  s.add_runtime_dependency(%q<warden>)
  
  s.add_development_dependency(%q<rake>)
  s.add_development_dependency(%q<rack-test>)
  s.add_development_dependency(%q<riot>)
  s.add_development_dependency(%q<timecop>)
  s.add_development_dependency(%q<simplecov>)
  s.add_development_dependency(%q<simplecov-html>)
  s.add_development_dependency(%q<trollop>)
end