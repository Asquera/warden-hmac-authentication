# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name        = "hmac"
  s.version     = "1.0"
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Florian Gilcher"]
  s.email       = ["florian.gilcher@asquera.de"]
  s.summary     = %q{A tiny HMAC implementation}
  s.description = %q{A tiny HMAC implementation in use at Asquera. Also includes
  a warden strategy.}
  
  s.files = %w( README.md Rakefile LICENSE )
  s.files += Dir.glob("lib/**/*")
  
  s.require_paths = ["lib"]
  
  s.add_runtime_dependency(%q<addressable>)
  s.add_runtime_dependency(%q<rack>)
  s.add_development_dependency(%q<yard>)
  s.add_development_dependency(%q<rdiscount>)
  s.add_development_dependency(%q<simplecov>)
  s.add_development_dependency(%q<simplecov-html>)
end