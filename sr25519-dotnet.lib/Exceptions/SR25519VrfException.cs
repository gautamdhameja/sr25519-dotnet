using System;

namespace sr25519_dotnet.lib.Exceptions
{
    public class SR25519VrfException : Exception
    {
        public SR25519VrfException(string message) :
            base(message)
        { }
    }
}
