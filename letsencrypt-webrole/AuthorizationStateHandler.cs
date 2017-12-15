using System.Threading;
using ACMESharp;
using ACMESharp.ACME;
using letsencrypt_webrole.Services;

namespace letsencrypt_webrole
{
	class AuthorizationStateHandler
	{
		private readonly AcmeClient _client;
		private readonly AuthorizationState _authorizationState;

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
			// let's retry some times, so that if the site is load-balanced it may hit the wrong server
			int tries = 0;
			while (true)
			{
				AuthorizationState currentState = _authorizationState;
				_client.SubmitChallengeAnswer(currentState, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);

				// have to loop to wait for server to stop being pending.
				while (currentState.Status == "pending")
				{
					Log.Information("Refreshing authorization...");
					Thread.Sleep(4000); // this has to be here to give ACME server a chance to think
					AuthorizationState newAuthzState = _client.RefreshIdentifierAuthorization(currentState);
					if (newAuthzState.Status != "pending")
						currentState = newAuthzState;
				}

				Log.Information($"Authorization Result: {currentState.Status}");
				if (currentState.Status != "valid" && ++tries == 3)
					throw new AuthorizationFailedException(currentState);
			}
		}
	}
}
