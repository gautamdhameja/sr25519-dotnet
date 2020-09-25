using Microsoft.VisualStudio.TestTools.UnitTesting;
using sr25519_dotnet.lib;

namespace sr25519_dotnet.test
{
    [TestClass]
    public class SR25519_Tests
    {
        [TestMethod]
        public void ShouldGenerateKeypair()
        {
            // Arrange.
            var seed = "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e";
            var expectedPublic = "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";

            // Act.
            var derived = SR25519.GenerateKeypairFromSeed(seed);

            // Assert.
            Assert.AreEqual(expectedPublic, Utils.ByteArrayToHexString(derived.Public));
        }

        [TestMethod]
        public void ShouldSignAndVerifyMessageString()
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
        public void ShouldSignAndVerifyMessageBytes()
        {
            // Arrange.
            var message1 = "010203040506070809";
            var message2 = "090807060504030201";

            // Act.
            var keys = SR25519.GenerateKeypairFromSeed(
                 "f6dbe0604959f8d4f53ef58754f44391c69cfc87f1b97872abef63161e18c885");
            var sig = SR25519.Sign(Utils.HexStringToByteArray(message1), keys);

            var verification1 = SR25519.Verify(Utils.HexStringToByteArray(message1), sig, keys.Public);
            var verification2 = SR25519.Verify(Utils.HexStringToByteArray(message2), sig, keys.Public);

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
            var cc = "14416c6963650000000000000000000000000000000000000000000000000000";
            var expectedPublic = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";

            // Act.
            var derived = SR25519.HardDeriveKeypair(keys, cc);

            // Assert.
            Assert.AreEqual(expectedPublic, Utils.ByteArrayToHexString(derived.Public));
        }

        [TestMethod]
        public void ShouldSoftDeriveKeypair()
        {
            // Arrange.
            var keys = SR25519.GenerateKeypairFromSeed(
                "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e");
            var cc = "0c666f6f00000000000000000000000000000000000000000000000000000000";
            var expectedPublic = "40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a";

            // Act.
            var derived = SR25519.SoftDeriveKeypair(keys, cc);

            // Assert.
            Assert.AreEqual(expectedPublic, Utils.ByteArrayToHexString(derived.Public));
        }

        [TestMethod]
        public void ShouldSoftDerivePublicKey()
        {
            // Arrange.
            var publicKey = "46ebddef8cd9bb167dc30878d7113b7e168e6f0646beffd77d69d39bad76b47a";
            var cc = "0c666f6f00000000000000000000000000000000000000000000000000000000";
            var expectedPublic = "40b9675df90efa6069ff623b0fdfcf706cd47ca7452a5056c7ad58194d23440a";

            // Act.
            var derived = SR25519.SoftDerivePublicKey(publicKey, cc);

            // Assert.
            Assert.AreEqual(expectedPublic, Utils.ByteArrayToHexString(derived));
        }
    }
}
