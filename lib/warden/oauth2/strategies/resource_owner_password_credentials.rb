require 'warden-oauth2'

module Warden
  module OAuth2
    module Strategies
      class ResourceOwnerPasswordCredentials < Client
        def valid?
          params['grant_type'] == 'password'
        end

        protected

        def model
          Warden::OAuth2.config.resource_owner_password_credentials_model
        end

        def client_authenticated
          if params['username'] && params['password']
            if client.valid?(username: params['username'], password: params['password'])
              if client.confirmed?(username: params['username'])
                super
              else
                fail('invalid_client')
                self.error_description = 'Please confirm your account prior to use our service'
              end
            else
              fail('invalid_client')
              self.error_description = 'Incorrect username or password'
            end
          else
            fail('invalid_request')
            self.error_description = 'Empty username or password'
          end
        end
      end
    end
  end
end
