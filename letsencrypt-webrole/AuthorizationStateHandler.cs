using System.Threading;
using ACMESharp;
using ACMESharp.ACME;
using letsencrypt_webrole.Services;

namespace letsencrypt_webrole
{
    class AuthorizationStateHandler
    {
        private readonly AcmeClient _client;
        private AuthorizationState _authorizationState;

        public AuthorizationStateHandler(AcmeClient client, AuthorizationState authorizationState)
        {
            _client = client;
            _authorizationState = authorizationState;
        }

        public HttpChallenge DecodeChallenge()
        {
            AuthorizeChallenge challenge = _client.DecodeChallenge(_authorizationState, AcmeProtocol.CHALLENGE_TYPE_HTTP);
            _authorizationState.Challenges = new[] { challenge };
            return (HttpChallenge)challenge.Challenge;
        }

        public void SubmitChallengeAnswer()
        {
            _client.SubmitChallengeAnswer(_authorizationState, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);

            // have to loop to wait for server to stop being pending.
            while (_authorizationState.Status == "pending")
            {
                Log.Information("Refreshing authorization...");
                Thread.Sleep(4000); // this has to be here to give ACME server a chance to think
                AuthorizationState newAuthzState = _client.RefreshIdentifierAuthorization(_authorizationState);
                if (newAuthzState.Status != "pending")
                    _authorizationState = newAuthzState;
            }

            Log.Information($"Authorization Result: {_authorizationState.Status}");
            if (_authorizationState.Status != "valid")
                throw new AuthorizationFailedException(_authorizationState);
        }
    }
}
