#require "mkmf"

#abort "missing malloc()" unless have_func "malloc"
#abort "missing free()"   unless have_func "free"

CURRENT_DIR = File.expand_path('../', __FILE__)
SRC_DIR = File.join(CURRENT_DIR, 'src')

CMAKE_COMMAND = [
  'cmake',
  '-DCMAKE_BUILD_TYPE=Release',
  "-DCMAKE_INSTALL_PREFIX=#{CURRENT_DIR}",
  '-DLANG=ruby',
  SRC_DIR
].join(' ')

system(CMAKE_COMMAND)

#create_makefile "my_malloc/my_malloc"
