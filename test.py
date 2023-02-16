import openfhe_pybind as OPY
import time 



if __name__ == "__main__":
  parameters = OPY.CryptoParameters()
  parameters.SetRingDim(1 << 12)
  parameters.SetSecurityLevel(OPY.SecurityLevel.HEStd_NotSet)
  parameters.SetScalingModSize(59)
  #parameters.SetScalingTechnique(OPY.ScalingTechnique.FLEXIBLEAUTO)
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
  numSlots = ringDim / 2
  print("ringDim", ringDim)
  print("numSlots", numSlots)
  levelBudget = [4,4]
  cc.EvalBootstrapSetup(levelBudget)


  keyPair = cc.KeyGen()
  print("done keygen")
  sk = keyPair.secretKey()
  print("sk", sk)

  #cc.EvalSumKeyGen(keyPair.secretKey())
  #print("done sum key gen")

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

  print(f'ptxt1={ptxt1}\n')
  c1 = cc.Encrypt(keyPair.publicKey(), ptxt1)
  c2 = cc.Encrypt(keyPair.publicKey(), ptxt2)
  print("done encryption")
  print(f"c1={c1}\n")
  print("\n\n\n")
  print("------------serialize---------------")

  print()
  print("cryptocontext serialize")
  print(OPY.cc_SerializeToFile("./data/cc.txt",cc))

  print()
  print("pubkey serialize")
  print(OPY.pubKey_SerializeToFile("./key/keypub.txt",keyPair.publicKey()))

  print()
  print("prvkey serialize")
  print(OPY.prvKey_SerializeToFile("./key/keyprv.txt",keyPair.secretKey()))
 
  #print()
  #print("serialize evalsumkey")
  #print(cc.SerializeEvalSumKey("./evalsum.txt"))

  print()
  print("serialize evalmultkey")
  print(cc.SerializeEvalMultKey("./key/evalmult.txt"))
  
  print()
  print("serialize rotatekey")
  print(cc.SerializeEvalAutomorphismKey("./key/evalam.txt"))

  print()
  print("ctext serialize")
  print(OPY.ctext_SerializeToFile("./data/ctext1.txt",c1))
  print(OPY.ctext_SerializeToFile("./data/ctext2.txt",c2))
  
  print("------------end---------------")
  print("\n\n\n")
  print("------------deserialize---------------")
  

  print("start")
  client_cc = OPY.cc_DeserializeFromFile("./data/cc.txt")
  print("cryptocontext deserialize")
  print(client_cc)
  print()

  client_publickey=OPY.pubKey_DeserializeFromFile("./key/keypub.txt")
  print("pubkey deserialize")
  print(client_publickey)
  print()

  client_privatekey=OPY.prvKey_DeserializeFromFile("./key/keyprv.txt")
  print("prvkey deserialize")
  print(client_privatekey)
  print()

  #print("evalsumkey desrialize")
  #print(client_cc.DeserializeEvalSumKey("./evalsum.txt"))
  #print()

  print("evalmultkey deserialize")
  print(client_cc.DeserializeEvalMultKey("./key/evalmult.txt"))
  print()

  print("evalamkey deserialize")
  print(client_cc.DeserializeEvalAutomorphismKey("./key/evalam.txt"))
  print()

  ctext1 = OPY.ctext_DeserializeFromFile("./data/ctext1.txt")
  ctext2 = OPY.ctext_DeserializeFromFile("./data/ctext2.txt")
  print("ctext deserialize")
  print(ctext1)
  print(ctext2)
  print()

  print("------------end---------------")


  print("\n\n\n")
  print("---------------client turn-------------------")
  

  #bootstrapkeyをserializeする方法が不明なため
  ringDim = client_cc.GetRingDimension()
  numSlots = ringDim / 2
  print("ringDim", ringDim)
  print("numSlots", numSlots)
  levelBudget = [4,4]
  client_cc.EvalBootstrapSetup(levelBudget)

  client_cc.EvalBootstrapKeyGen(client_privatekey, int(numSlots))
  print("done bsk gen")


  ctxt_bs = client_cc.EvalBootstrap(ctext1)
  ctxt_add = client_cc.EvalAdd(ctext1, ctext2)
  ctxt_sub = client_cc.EvalSub(ctext1, ctext2)
  ctxt_mult = client_cc.EvalMultAndRelinearize(ctext1, ctext2)
  ctxt_mult_s = client_cc.EvalMult(ctext1, 2.0)
  ctxt_rotate = client_cc.EvalRotate(ctext1, 1)

  dec = client_cc.Decrypt(ctxt_bs, client_privatekey)
  d_add = client_cc.Decrypt(ctxt_add, client_privatekey)
  d_sub = client_cc.Decrypt(ctxt_sub, client_privatekey)
  d_mult = client_cc.Decrypt(ctxt_mult, client_privatekey)
  d_mult_s = client_cc.Decrypt(ctxt_mult_s, client_privatekey)
  d_rotate = client_cc.Decrypt(ctxt_rotate, client_privatekey)

  print("calc & decrypt done")

  print("print client decrypt") 
  dec.SetLength(3)
  print("dec")
  print(f"dec type={dec}")
  print(f'{dec.Print()}')
  d_add.SetLength(3)
  print("add")
  d_add.Print()
  d_sub.SetLength(3)
  print("sub")
  d_sub.Print()
  d_mult.SetLength(3)
  print("mult")
  d_mult.Print()
  d_mult_s.SetLength(3)
  print("mult_s")
  d_mult_s.Print()
  d_rotate.SetLength(3)
  print("rotate")
  d_rotate.Print()
  print("end print client")
  print("\n\n\n")


  #server 

  print("---------------server turn-------------------")
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
  
  print("Decrypt and calc and Print")
  ptxt1=cc.Decrypt(c1,keyPair.secretKey())
  ptxt2=cc.Decrypt(c2,keyPair.secretKey())
  txt1=ptxt1.GetRealPackedValue()
  txt2=ptxt2.GetRealPackedValue()

  ptxt_add=[]
  for i in range(len(txt1)):
      tmp=txt1[i]+txt2[i]
      ptxt_add.append(tmp)
  encd1=cc.MakeCKKSPackedPlaintext(ptxt_add)
  c_add=cc.Encrypt(keyPair.publicKey(),encd1)
  c_dec=cc.Decrypt(c_add,keyPair.secretKey())
  c_dec.SetLength(3)
  c_dec.Print()
  print("end\n\n\n")

  print("calc & decrypt done")

  print("print server decrypt")
  dec.SetLength(3)
  print("dec")
  dec.Print()
  d_add.SetLength(3)
  print("add")
  d_add.Print()
  d_sub.SetLength(3)
  print("sub")
  d_sub.Print()
  d_mult.SetLength(3)
  print("mult")
  d_mult.Print()
  d_mult_s.SetLength(3)
  print("mult_s")
  d_mult_s.Print()
  d_rotate.SetLength(3)
  print("rotate")
  d_rotate.Print()
  print("end print server") 

