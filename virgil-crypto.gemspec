# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'virgil/os'
require 'virgil/crypto/version'

abort "Windows is not supported yet." if OS.windows?


Gem::Specification.new do |spec|
  spec.name          = "virgil-crypto"
  spec.version       = Virgil::Crypto::VERSION
  spec.authors       = ["Dmitriy Dudkin", "Vasilina Bezuglaya", "Sergey Seroshtan"]
  spec.email         = ["dudkin.dmitriy@gmail.com", "vbezuglaya@virgilsecurity.net", "sseroshtan@virgilsecurity.com"]

  spec.summary       = %q{Virgil Crypto library wrapper}
  spec.description   = %q{virgil-crypto provides:
                        Encrypt data
                        Decrypt data
                        Sign data
                        Verify data}
  spec.homepage      = "http://github.com/VirgilSecurity/virgil-crypto-ruby"
  spec.licenses      = ['BSD-3-Clause']

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.extensions = [ 'ext/rakefile.rb']
  spec.required_ruby_version = '>= 2.1.10'
  spec.add_development_dependency "bundler", "~> 1.12"
  spec.add_development_dependency "rake-compiler", "~> 1.0"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "minitest-reporters", "~> 1.1"

  current_dir = File.expand_path(File.dirname(__FILE__))

  # get an array of submodule dirs by executing 'pwd' inside each submodule
  `git submodule --quiet foreach pwd`.split($\).each do |submodule_path|
    # for each submodule, change working directory to that submodule
    Dir.chdir(submodule_path) do

      # issue git ls-files in submodule's directory
      submodule_files = `git ls-files -z`.split("\x0")

      # prepend the submodule path to create absolute file paths
      submodule_files_fullpaths = submodule_files.map do |filename|
        "#{submodule_path}/#{filename}"
      end

      # remove leading path parts to get paths relative to the gem's root dir
      # (this assumes, that the gemspec resides in the gem's root dir)
      submodule_files_paths = submodule_files_fullpaths.map do |filename|
        filename.gsub "#{current_dir}/", ""
      end


      # add relative paths to gem.files
      spec.files += submodule_files_paths
    end
  end
end

