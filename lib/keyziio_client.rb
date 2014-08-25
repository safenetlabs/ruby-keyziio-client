require 'keyziio_client/version.rb'
require 'keyziio_client/kzrestclient.rb'
require 'keyziio_client/kzcrypt.rb'

class KZClient
  def initialize
    @kzcrypt = KZCrypt.new()
  end

  def inject_user_key (user_private_key_pem, key_id)
    # Injects the user's private_key and key_id so that they can unwrap Keyziio data keys.
    @kzcrypt.inject_user_key(user_private_key_pem, key_id)
  end

  def encrypt_file (in_file, out_file, key_id)
    #'encrypt: Encrypts input_file with key_id to output_file.'
    @kzcrypt.encrypt_file(in_file, out_file, key_id)
  end

  def decrypt_file (in_file, out_file)
    # 'decrypt: Decrypts input file to output file.  Gets the key_id from the file header.'
    @kzcrypt.decrypt_file(in_file, out_file)
  end

  def encrypt_buffer (buf_in, key_id)
    # Encrypts buf_in using key_id.  It will create the key if it has to.
    @kzcrypt.encrypt_buffer(buf_in, key_id)
  end

  def decrypt_buffer (buf_in)
    # Decrypts buf_in using key_id.  It will create the key if it has to.
    @kzcrypt.decrypt_buffer(buf_in)
  end
end

