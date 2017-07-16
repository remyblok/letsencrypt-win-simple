using System;
using System.Runtime.Serialization;
using ACMESharp;

namespace letsencrypt_webrole
{
    [Serializable]
    public class AuthorizationFailedException : Exception
    {
        public AuthorizationState AuthorizationState { get; }

        public AuthorizationFailedException(AuthorizationState state)
            : base($"Authorization Failed {state.Status}")
        {
            AuthorizationState = state;
        }

        protected AuthorizationFailedException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }

        /// <inheritdoc />
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
        }
    }
}
