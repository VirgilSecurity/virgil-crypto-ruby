require 'mkmf'

CMAKE = find_executable "cmake"
abort "cmake >= 3.2 is required" unless CMAKE

SCRIPT_DIR = File.expand_path('../', __FILE__)
SRC_DIR = File.join(SCRIPT_DIR, 'src')
CURRENT_DIR = Dir.pwd
LIB_DIR = File.expand_path('../../lib', SCRIPT_DIR)
INSTALL_DIR = File.join(LIB_DIR, 'virgil', 'crypto')

CMAKE_COMMAND = [
  CMAKE,
  '-DCMAKE_BUILD_TYPE=Release',
  "-DCMAKE_INSTALL_PREFIX=#{CURRENT_DIR}",
  "-DINSTALL_API_DIR_NAME=#{INSTALL_DIR}",
  "-DINSTALL_LIB_DIR_NAME=#{INSTALL_DIR}",
  '-DLANG=ruby',
  SRC_DIR
].join(' ')

system(CMAKE_COMMAND)
