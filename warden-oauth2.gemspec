# -*- encoding: utf-8 -*-
require File.expand_path('../lib/warden/oauth2/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ['aceunreal']
  gem.description   = 'OAuth 2.0 strategies for Warden'
  gem.summary       = 'OAuth 2.0 strategies for Warden'
  gem.homepage      = 'https://github.com/aceunreal/warden-oauth2'

  gem.executables   = `git ls-files -- bin/*`.split("\n").map { |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = 'warden-oauth2'
  gem.require_paths = ['lib']
  gem.version       = Warden::OAuth2::VERSION
  gem.licenses      = ['MIT']
  gem.required_ruby_version = '>= 1.9.3'

  gem.add_dependency 'warden'
  gem.add_development_dependency 'rake'
  gem.add_development_dependency 'rspec'
  gem.add_development_dependency 'rack-test'
end
