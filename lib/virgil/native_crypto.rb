require 'virgil/crypto/version'
require 'virgil/os'
require 'net/http'
require 'open-uri'
require 'zlib'
require 'fileutils'
require 'rake'

class NativeCrypto
  LIBRARY_LIST_URL = "https://cdn.virgilsecurity.com/virgil-crypto/ruby/"

  def self.load_library
    #
    #
    # library_file_name = 'virgil_crypto_ruby.'
    # library_file_name += required_library_os == 'linux' ? 'os' : 'bundle'
    #
    # crypto_folder_path = "#{lib_path}/virgil/crypto"
    #
    #
    #   download_library(get_library_path, library_file_name, crypto_folder_path)

#
#     rake = Rake.application
#     rake.init
# # you can import addition *.rake files
#     rake.add_import '../Rakefile'
#     rake.load_rakefile
#     rake['native_sources:run_cmake'].invoke()
  end


  def self.get_library_path
    body = get_https(LIBRARY_LIST_URL)
    abort "Can't download native library. Please try later." unless body
    ruby_version = RUBY_VERSION.sub(/\.[^\.]+$/, "")
    href_template = /virgil-crypto-#{required_library_version}\b-.+\b?-ruby-#{ruby_version}-#{required_library_os}(?!tgz).+tgz"/
    href_list = body.scan href_template

    if href_list.last.nil?
      abort "Sorry. Correct version #{required_library_version} of Native Library is missing."
    end
    puts "Downloading from #{href_list.last}"
    href_list.last.sub(/"$/, '')

  end

  def self.get_https(url)
    uri = URI(url)
    Net::HTTP.start(uri.host, uri.port,
                    :use_ssl => true) do |http|
      http.read_timeout = 100
      request = Net::HTTP::Get.new uri
      response = http.request request
      case response
        when Net::HTTPSuccess
          response.body
        when Net::HTTPServerError
          warn "#{response.message}: try again later?"
          nil
        else
          warn response.message
          nil
      end
    end
  end

  def self.required_library_version
    Virgil::Crypto::VERSION.scan(/\d+\.\d+\.\d+(\D+\d*)$/) do |postfix|
      return Virgil::Crypto::VERSION.sub(postfix.last, '')
    end
    return ''
  end

  def self.required_library_os
    if OS.linux?
      "linux"
    elsif OS.mac?
      "darwin"
    end
  end

  def self.download_library(source_path, file_name, folder_path)

      system('mkdir -p tmp')
      archive_path = 'tmp/native_library.tar.gz'

      open(archive_path, 'w') do |local_file|
        begin
          open(LIBRARY_LIST_URL + source_path) do |remote_file|
            local_file.write(Zlib::GzipReader.new(remote_file).read)
          end
        rescue Exception => e
          abort "Can't download native library by reason: #{e}"
        end
      end

      library_folder_name = source_path.sub('.tgz', '')

      system("tar xvf #{archive_path} -C tmp/")


      system("cp tmp/#{library_folder_name}/lib/#{file_name} #{folder_path}/#{file_name}")
      system('rm -rf tmp')

  end

  def self.lib_path
    File.expand_path('../../..', __FILE__) + "/lib"
  end


end
