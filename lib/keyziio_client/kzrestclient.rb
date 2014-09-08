require 'logger'
require 'json'
require 'rest-client'

class Unauthorized < Exception
  # Unauthorized to get resource
end

class ConnectionFailure < Exception
  # Not connected to the server at all
end

class ResourceNotFound < Exception
  # Failed to get resource from keyziio server
end


class KZRestClient < Object
    def initialize (keychain_id, access_token, server_url)
      @base_url = server_url
      @keychain_id = keychain_id
      @api_path = 'api/v1/client/keychains/'
      @access_token = access_token
    end

    def _url (path)
      return '%s/%s' % [@base_url, path]
    end

    def get_user_key (pub_key_pem)
      begin
        RestClient.post _url(@api_path + @keychain_id.to_s + '/wrap'), {'public_key' => pub_key_pem},
                                              {:content_type => :json,
                                              :accept => :json,
                                              :user_agent => 'Keyziio Ruby Client',
                                              :authorization => "Bearer #{@access_token}"}
      rescue RestClient::Unauthorized
        raise Unauthorized
      rescue SocketError => e
        raise ConnectionFailure, e.message
      rescue RestClient::ResourceNotFound => e
        raise ResourceNotFound, e.message
      end
    end

    def get_key (key_id)
      begin
        RestClient.get _url(@api_path + @keychain_id.to_s + '/data_keys/' + key_id.to_s),
                       {:content_type => :json,
                        :accept => :json,
                        :user_agent => 'Keyziio Ruby Client',
                        :authorization => "Bearer #{@access_token}"}
      rescue RestClient::Unauthorized
        raise Unauthorized
      rescue SocketError => e
        raise ConnectionFailure, e.message
      rescue RestClient::ResourceNotFound => e
        raise ResourceNotFound, e.message
      end
    end

    def post_data_key (key_name, key_type, key, iv)
      begin
        RestClient.post _url(@api_path + @keychain_id.to_s + '/data_keys'), {'name' => key_name,
                                                                                 'type' => key_type,
                                                                                 'key' => key,
                                                                                 'iv' => iv},
                                                                                {:content_type => :json,
                                                                                :accept => :json,
                                                                                :user_agent => 'Keyziio Ruby Client',
                                                                                :authorization => "Bearer #{@access_token}"}
      rescue RestClient::Unauthorized
        raise Unauthorized
      rescue SocketError => e
        raise ConnectionFailure, e.message
      end
    end
end

if __FILE__ == $0
  rc = KZRestClient.new()
  #resp = rc.get_key('my_test_key_1', 'c87f689e-85d5-46b3-81ba-ce9666371d45')
  resp = rc.get_key('my_test_key_1')
  print resp ? resp : 'not found'
end
