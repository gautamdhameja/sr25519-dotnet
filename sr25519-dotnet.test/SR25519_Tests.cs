using Microsoft.VisualStudio.TestTools.UnitTesting;
using sr25519_dotnet.lib;
using System;

namespace sr25519_dotnet.test
{
    [TestClass]
    public class SR25519_Tests
    {
        [TestMethod]
        public void ShouldSignAndVerify()
        {
            // Arrange.
            var message1 = "positive test message";
            var message2 = "negative test message";

            // Act.
            var keys = SR25519.GenerateKeypairFromSeed(
                "f6dbe0604959f8d4f53ef58754f44391c69cfc87f1b97872abef63161e18c885");
            var sig = SR25519.Sign(message1, keys);
            var verification1 = SR25519.Verify(message1, sig, keys.Public);
            var verification2 = SR25519.Verify(message2, sig, keys.Public);

            // Assert.
            Assert.IsTrue(verification1);
            Assert.IsFalse(verification2);
        }

        [TestMethod]
        public void ShouldHardDeriveKeypair()
        {
            // Arrange.
            var keys = SR25519.GenerateKeypairFromSeed(
                "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
            var cc = "14416c6963650000000000000000000000000000000000000000000000000000"; // Alice
            var expected_public = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

            // Act.
            var derived = SR25519.HardDeriveKeypair(keys, cc);

            // Assert.
            Assert.AreEqual(expected_public, Utils.ByteArrayToHexString(derived.Public));
        }
    }
}
