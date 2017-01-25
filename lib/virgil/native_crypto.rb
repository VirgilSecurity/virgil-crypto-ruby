require 'virgil/crypto/version'
require 'virgil/os'
require 'net/http'
require 'open-uri'
require 'zlib'
class NativeCrypto
  LIBRARY_LIST_URL = "https://cdn.virgilsecurity.com/virgil-crypto/ruby/"

  def self.load_library
    library_path = get_library_path
    download_library(library_path)

  end


  def self.get_library_path
    body = get_https(LIBRARY_LIST_URL)
    abort "Can't download native library. Please try later." unless body

    href_template = /virgil-crypto-#{required_library_version}-ruby-2.0-#{required_library_os}[^\.]+\.tgz/
    body.match(href_template)
    href_list = body.scan href_template
    href_list.last

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
    Virgil::Crypto::VERSION.sub(/\D\d+$/, "")
  end

  def self.required_library_os
    if OS.linux?
      "linux"
    elsif OS.mac?
      "darwin"
    end
  end

  def self.download_library(library_path)
    system("mkdir tmp")
    archive_path = "tmp/native_library.tar.gz"
    open(archive_path, 'w') do |local_file|
      begin
      open(LIBRARY_LIST_URL + library_path) do |remote_file|
        local_file.write(Zlib::GzipReader.new(remote_file).read)
      end
      rescue Exception => e
       abort "Can't download native library by reason: #{e}"
      end
    end

      library_folder_name = library_path.sub(".tgz", "")

      system("tar xvf #{archive_path} -C tmp/")
      system("cp tmp/#{library_folder_name}/lib/virgil_crypto_ruby.so #{lib_folder_path}/virgil/crypto/native.so")
      system("rm -rf tmp/*")
  end

  def self.lib_folder_path
    File.expand_path('../../..',__FILE__) + "/lib"
  end


end
