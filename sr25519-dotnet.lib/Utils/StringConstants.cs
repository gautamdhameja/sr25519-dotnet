using System;
using System.Collections.Generic;
using System.Text;

namespace sr25519_dotnet.lib
{
    public static class StringConstants
    {
        public const string BadKeySizeMessage = "Cannot instantiate keypair. Public or secret key size is invalid.";

        public const string BadChaincodeSizeMessage = "Chaincode size is invalid.";

        public static readonly string BadVrfResultSizeMessage =
            $"Invalid VRF result: should be { Constants.SR25519_VRF_OUTPUT_SIZE + Constants.SR25519_VRF_PROOF_SIZE } bytes.";

        public static readonly string BadVrfOutputSizeMessage =
            $"Invalid VRF output: should be { Constants.SR25519_VRF_OUTPUT_SIZE } bytes.";

        public static readonly string BadVrfProofSizeMessage =
            $"Invalid VRF proof: should be { Constants.SR25519_VRF_PROOF_SIZE } bytes.";

        public static readonly string BadVrfTresholdSizeMessage =
            $"Invalid VRF threshold: must be { Constants.SR25519_VRF_THRESHOLD_SIZE } bytes.";
    }
}
