# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'keyziio_client/version'

Gem::Specification.new do |spec|
  spec.name          = "keyziio_client"
  spec.version       = KeyziioClient::VERSION
  spec.authors       = ["hsharma001"]
  spec.email         = ["hsharma@safenet-inc.com"]
  spec.summary       = %q{"Keyziio Client"}
  spec.description   = %q{"The keyziio client library is intended to be integrated into applications wanting to encrypt or decrypt files using the keyziio service"}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = Dir["{lib}/**/*.rb", "{lib}/**/*.rake", "{lib}/**/*.yml", "*.md"]  #`git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_runtime_dependency 'rest-client'

  spec.add_development_dependency "bundler", "~> 1.6"
  spec.add_development_dependency "rake", "~> 10.0"
end
