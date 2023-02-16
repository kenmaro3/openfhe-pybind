import openfhe_pybind as OPY


def run_demo_pre():
    parameters = OPY.CryptoParameters()
    parameters.SetRingDim(1 << 12)
    parameters.SetSecurityLevel(OPY.SecurityLevel.HEStd_NotSet)
    parameters.SetScalingModSize(59)
    parameters.SetFirstModSize(60)
    depth = parameters.GetBootstrapDepth(1, OPY.SecretKeyDist.UNIFORM_TERNARY)
    parameters.SetMultiplicativeDepth(depth)
    print("depth ", depth)
    print("parameters", parameters)
    cc = OPY.generate_context_from_parameters(parameters)
    print(f'cc={cc}')

    cc.Enable(OPY.PKESchemeFeature.PKE)
    cc.Enable(OPY.PKESchemeFeature.PRE)
    cc.Enable(OPY.PKESchemeFeature.KEYSWITCH)
    cc.Enable(OPY.PKESchemeFeature.LEVELEDSHE)
    cc.Enable(OPY.PKESchemeFeature.ADVANCEDSHE)
    cc.Enable(OPY.PKESchemeFeature.FHE)

    ringDim = cc.GetRingDimension()
    print("ringDim",ringDim)


    keyPair1 = cc.KeyGen()
    print("Runninng Alice key generation (used for source data)...")

    IntIndex = [1,2,3,4,5,6,7,8,9,10]
    print(f"input = {IntIndex}")

    pt = cc.MakeCKKSPackedPlaintext(IntIndex)

    ct1 = cc.Encrypt(keyPair1.publicKey(),pt)

    dec1 = cc.Decrypt(ct1,keyPair1.secretKey())

    dec1.SetLength(10)

    keyPair2 = cc.KeyGen()
    print("Runninng Bob key generation ...")

    print("Generating proxy re-encryption key ...")
    reenckey12 = cc.ReKeyGen(keyPair1.secretKey(),keyPair2.publicKey());

    ct2 = cc.ReEncrypt(ct1,reenckey12)

    dec12 = cc.Decrypt(ct2,keyPair2.secretKey())

    dec12.SetLength(10)

    unpack0 = pt.GetRealPackedValue()
    print(f"unpack0={unpack0}\n")
    unpack1 = dec1.GetRealPackedValue()
    print(f"unpack1={unpack1}\n")
    unpack2 = dec12.GetRealPackedValue()
    print(f"unpack2={unpack2}\n")
    good = True

    """
    for i in range(10):
        if unpack1[i] < 0:
            unpack1 += plaintextmodules
        if unpack2[i] < 0:
            unpack2 += plaintextmodules
    
    for i in range(10):
        if unpack0[i] != unpack1[i] or unpack0[i] != unpack2[i]:
            good = False
    
    if good :
        print("pass")
    else :
        print("fails")
    """
    return good


if __name__ == "__main__":
    passed = run_demo_pre()
    if passed==False:
        print("False")
        exit(1)
    print("True")
    exit(0)



