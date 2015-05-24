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
            if client_valid? && client_confirmed?
              super
            elsif client_valid?
              fail('invalid_client')
              self.error_description = 'Please confirm your account prior to use our service'
            else
              fail('invalid_client')
              self.error_description = 'Incorrect username or password'
            end
          else
            fail('invalid_request')
            self.error_description = 'Empty username or password'
          end
        end

        private

        def client_valid?
          client.valid?(username: params['username'].downcase, password: params['password'])
        end

        def client_confirmed?
          client.confirmed?(username: params['username'].downcase)
        end
      end
    end
  end
end
