# KeyziioClient

The keyzio client gem is intended to be integrated into applications wanting to encrypt or decrypt files using the keyziio service. It includes a sample script (keyziio_test.rb) and the keyziio library itself which is currently exposed as a ruby gem.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'keyziio_client'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install keyziio_client

## Usage

Create an instance of keyziio client,

<code>Keyziio.new()</code>

Then, 
    
<code>login_user some_username</code>

This will create a user if one does not exist and retrieve the user's private key from the ASP (Application Service Provider) and injects it into the keyziio library.

<code>inject_user_key user_private_key_pem a_key_identifier</code>

Injects the users private key and id so that they can unwrap keyziio data keys. The private key is expected to be in PEM format.

<code>encrypt_file an_input_file an_output_file a_key_identifier</code>

This will encrypt 'an_input_file' with a key ientified by 'a_key_identifier' and write it to 'an_output_file'. If the key does not exist it will be created.

<code>decrypt_file an_encrypted_input_file an_output_file</code>

This will decrypt the encrypted file 'an_encrypted_input_file' to 'an_output_file'. The key identifier is automatically extracted from the encrypted file.

## Contributing

1. Fork it ( https://github.com/[my-github-username]/keyziio_client/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
