#require_relative 'version.rb'
require 'base64'
require 'openssl'
require_relative 'kzrestclient.rb'
require_relative 'kzheader.rb'

class InvalidKeyException < Exception
  # Cannot unwrap this key
  def to_s
      return 'Cannot unwrap this key'
  end
end

class KZCrypt
  # File crypto operations for Keyziio

  def initialize
    @chunk_length = 1024
    @rest_client = KZRestClient.new()
    @cipher_algo = 'AES-256-CBC'
    @cipher_block_size = 16
  end

  def inject_user_key (user_private_key_pem, user_id)
    # Injects the users private key and id so that they can unwrap keyziio data keys
    # The private key is expected to be in PEM format
    @user_private_key = OpenSSL::PKey::RSA.new user_private_key_pem
    @user_id = user_id
  end

  def _process_file (file_in, file_out, encrypt, key_id=nil)
    if not encrypt
      # get the key id from the file itself
      header = KZHeader.new()
      header_length = header.decode_from_file(file_in)
      key_id = header.key_id
    end
    cipher = _init_cipher(key_id, encrypt)

    plain_text_length = File.stat(file_in).size
    File.open(file_in, 'rb') do |f_in|
      if not encrypt
        f_in.seek(header_length)
      end
      File.open(file_out, 'wb') do |f_out|
        if encrypt
          # create a header
          header = KZHeader.new()
          header.key_id = key_id
          f_out.write(header.encode())
        end
        bytes_remaining = plain_text_length
        while bytes_remaining > 0
          bytes_to_read = bytes_remaining < @chunk_length ? bytes_remaining : @chunk_length
          data_in = f_in.read(bytes_to_read)
          bytes_remaining -= bytes_to_read
          if encrypt
            f_out.write(_encrypt_chunk(cipher, data_in, bytes_remaining <= 0 ))
          else
            f_out.write(_decrypt_chunk(cipher, data_in, bytes_remaining <= 0 ))
          end
        end
      end
    end
  end

  def encrypt_file (file_in, file_out, key_id)
    # Encrypts file_in using key_id.  It will create the key if it has to.
    _process_file(file_in, file_out, true, key_id)
  end

  def decrypt_file (file_in, file_out)
    # Decrypts file_in using key_id.  It will create the key if it has to.
    _process_file(file_in, file_out, false)
  end

  def _encrypt_chunk (cipher, data_in, is_last_chunk)
    if data_in.length == 0
      return ''
    end
    if is_last_chunk
      pad_length = @cipher_block_size - (data_in.length % @cipher_block_size)
      if pad_length == 0
        pad_length = @cipher_block_size
      end
      data_in += pad_length.chr * pad_length
      return cipher.update(data_in) << cipher.final
    end
    return cipher.update(data_in)
  end

  def _decrypt_chunk (cipher, data_in, is_last_chunk)
    if data_in.length == 0
      return ''
    end
    data_out = cipher.update(data_in)
    if is_last_chunk
      data_out << cipher.final
    end
    return !is_last_chunk ? data_out : data_out[0..-(data_out[-1]).ord]
  end

  def _init_cipher (key_id, encrypt)
    key_json = @rest_client.get_key(key_id, @user_id)
    # Key is encrypted under the user key, we have to decrypt it
    wrapped_key = Base64.decode64(JSON.parse(key_json)['key'])
    begin
      raw_key = @user_private_key.private_decrypt(wrapped_key, OpenSSL::PKey::RSA::PKCS1_PADDING)
    rescue
    end

    iv = Base64.decode64(JSON.parse(key_json)['iv'])
    cipher = OpenSSL::Cipher.new(@cipher_algo)
    if encrypt
      cipher.encrypt
    else
      cipher.decrypt
    end
    cipher.iv = iv
    cipher.key = raw_key
    # We take care of padding
    cipher.padding = 0
    return cipher
  end
end
