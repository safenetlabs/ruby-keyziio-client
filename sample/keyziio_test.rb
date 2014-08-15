# A sample client that makes use of the keyziio library
require 'keyziio_client'

class KzTest
  def initialize
      @keyziio = Keyziio.new()
  end

  def do_login (username)
    # 'login: Logs the user in and sets up the users keyziio session.  Users are created automatically.  Usage: login <username>'
    if @keyziio.is_user_logged_in
      print "Already logged in as #{@keyziio.username}\n"
      return
    end

    print "logging #{username} in...\n"
    @keyziio.login_user(username)
    print "Successfully retrieved user key and ignited keyziio client\n"
    print "done\n"
  end
    
  def do_encrypt (*args)
    #'encrypt: Encrypts input_file with key_id to output_file: Usage: encrypt <input_file> <output_file> <key_id>'
    raise ArgumentError, 'Invalid arguments.  Usage: encrypt <input_file> <output_file> <key_id>' if args.length != 3
    in_file, out_file, key_id = *args
    print "encrypting #{in_file} with key:#{key_id}...\n"
    @keyziio.encrypt_file(in_file, out_file, key_id)
    print "done\n"
  end

  def do_decrypt (*args)
    # 'decrypt: Decrypts input file to output file.  Gets the key_id from the file header.  Usage: decrypt <input_file> <output_file>'
    raise ArgumentError, 'Invalid arguments.  Usage: decrypt <input_file> <output_file>' if args.length != 2
    in_file, out_file = *args
    print "decrypting #{in_file}...\n"
    @keyziio.decrypt_file(in_file, out_file)
    print "done\n"
  end
end

if __FILE__ == $0
  shell = KzTest.new()
  shell.do_login('billy')
  shell.do_encrypt('README.md', 'readme_rb.enc', 'ruby_test_key1')
  shell.do_decrypt('readme_rb.enc', 'readme.dec')
end
