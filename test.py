import openfhe_pybind as OPY

if __name__ == "__main__":
  parameters = OPY.CryptoParameters();
  parameters.SetRingDim(1 << 12);
  parameters.SetSecurityLevel(OPY.SecurityLevel.HEStd_NotSet)
  parameters.SetScalingModSize(59)
  #parameters.SetScalingTechnique(OPY.ScalingTechnique.FLEXIBLEAUTO)
  parameters.SetFirstModSize(60)
  depth = parameters.GetBootstrapDepth(1, OPY.SecretKeyDist.UNIFORM_TERNARY)
  parameters.SetMultiplicativeDepth(depth)
  print("depth ", depth)
  print("parameters", parameters)

  cc = OPY.generate_context_from_parameters(parameters)
  cc.Enable(OPY.PKESchemeFeature.PKE)
  cc.Enable(OPY.PKESchemeFeature.PRE)
  cc.Enable(OPY.PKESchemeFeature.KEYSWITCH)
  cc.Enable(OPY.PKESchemeFeature.LEVELEDSHE)
  cc.Enable(OPY.PKESchemeFeature.ADVANCEDSHE)
  cc.Enable(OPY.PKESchemeFeature.FHE)


  ringDim = cc.GetRingDimension()
  numSlots = ringDim / 2
  print("ringDim", ringDim)
  print("numSlots", numSlots)
  levelBudget = [4,4]
  cc.EvalBootstrapSetup(levelBudget)


  keyPair = cc.KeyGen()
  print("done keygen")
  sk = keyPair.secretKey()
  print("sk", sk)
  cc.EvalMultKeyGen(keyPair.secretKey())
  print("done mult key gen")
  cc.EvalBootstrapKeyGen(keyPair.secretKey(), int(numSlots))
  print("done bsk gen")

  rotateIndex = [1, 2, 3]
  cc.EvalRotateKeyGen(keyPair.secretKey(), rotateIndex)
  print("done rotate key gen")

  p1 = [1, 2, 3];
  p2 = [1, 0, 0];
  print("will create encode")
  ptxt1 = cc.MakeCKKSPackedPlaintext(p1)
  ptxt2 = cc.MakeCKKSPackedPlaintext(p2)
  print("done encoding")
  ptxt1.SetLength(3)
  ptxt1.Print()

  print(ptxt1)
  c1 = cc.Encrypt(keyPair.publicKey(), ptxt1)
  c2 = cc.Encrypt(keyPair.publicKey(), ptxt2)
  print("done encryption")
  dec1 = cc.Decrypt(c1, keyPair.secretKey())
  dec1.SetLength(3)
  dec1.Print()

  c1 = cc.Encrypt(keyPair.publicKey(), ptxt1)
  c2 = cc.Encrypt(keyPair.publicKey(), ptxt2)

  ctxt_bs = cc.EvalBootstrap(c1)

  ctxt_add = cc.EvalAdd(c1, c2)
  ctxt_sub = cc.EvalSub(c1, c2)
  ctxt_mult = cc.EvalMultAndRelinearize(c1, c2)
  ctxt_mult_s = cc.EvalMult(c1, 2.0)
  ctxt_rotate = cc.EvalRotate(c1, 1)

  dec = cc.Decrypt(ctxt_bs, keyPair.secretKey())
  d_add = cc.Decrypt(ctxt_add, keyPair.secretKey())
  d_sub = cc.Decrypt(ctxt_sub, keyPair.secretKey())
  d_mult = cc.Decrypt(ctxt_mult, keyPair.secretKey())
  d_mult_s = cc.Decrypt(ctxt_mult_s, keyPair.secretKey())
  d_rotate = cc.Decrypt(ctxt_rotate, keyPair.secretKey())
  dec.SetLength(3)
  dec.Print()
  d_add.SetLength(3)
  d_add.Print()
  d_sub.SetLength(3)
  d_sub.Print()
  d_mult.SetLength(3)
  d_mult.Print()
  d_mult_s.SetLength(3)
  d_mult_s.Print()
  d_rotate.SetLength(3)
  d_rotate.Print()
