#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <memory>
#include "stdio.h"
#include <vector>

#include "openfhe.h"


#include "utils/serial.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/evalkey.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"



namespace py = pybind11;

using namespace lbcrypto;
using namespace std;


CryptoContext<DCRTPoly> generate_context_from_parameters(const CCParams<CryptoContextCKKSRNS>& params) {
    CryptoContext<DCRTPoly> cc = CryptoContextCKKSRNS::genCryptoContext(params);
    //return *cc.get();
    return cc;
}


PYBIND11_MODULE(openfhe_pybind, m)
{

  //std::shared_ptr<>
  m.def("generate_context_from_parameters", &generate_context_from_parameters);

  m.def("cc_SerializeToFile", [](const std::string& filename, const std::shared_ptr<CryptoContextImpl<DCRTPoly>> obj){
         return Serial::SerializeToFile(filename,obj,SerType::BINARY);
  });
  m.def("cc_DeserializeFromFile", [](const std::string& filename){
		 std::shared_ptr<CryptoContextImpl<DCRTPoly>> obj;
		 obj->ClearEvalSumKeys();
		 obj->ClearEvalMultKeys();
		 obj->ClearEvalAutomorphismKeys();
		 lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts();
         Serial::DeserializeFromFile(filename,obj,SerType::BINARY);
         return obj;
  });


  m.def("pubKey_SerializeToFile", [](const std::string& filename, const std::shared_ptr<PublicKeyImpl<DCRTPoly>> obj){
		 return Serial::SerializeToFile(filename,obj,SerType::BINARY);
  });
  m.def("pubKey_DeserializeFromFile", [](const std::string& filename){
		 std::shared_ptr<PublicKeyImpl<DCRTPoly>> obj;
		 Serial::DeserializeFromFile(filename,obj,SerType::BINARY);
		 return obj;
  });

  m.def("prvKey_SerializeToFile", [](const std::string& filename, const std::shared_ptr<PrivateKeyImpl<DCRTPoly>> obj){
         return Serial::SerializeToFile(filename,obj,SerType::BINARY);
  });
  m.def("prvKey_DeserializeFromFile", [](const std::string& filename){
         std::shared_ptr<PrivateKeyImpl<DCRTPoly>> obj;
		 Serial::DeserializeFromFile(filename,obj,SerType::BINARY);
		 return obj;
  });

  m.def("ctext_SerializeToFile", [](const std::string& filename,std::shared_ptr<CiphertextImpl<DCRTPoly>> obj){
         return Serial::SerializeToFile(filename,obj,SerType::BINARY);
  });
  m.def("ctext_DeserializeFromFile", [](const std::string& filename){
		 std::shared_ptr<CiphertextImpl<DCRTPoly>> obj;
		 Serial::DeserializeFromFile(filename,obj,SerType::BINARY);
		 return obj;
  });
  
  //m.def("ReleaseAllContexts",&lbcrypto::CryptoContextFactory<lbcrypto::DCRTPoly>::ReleaseAllContexts);



  py::enum_<PKESchemeFeature>(m, "PKESchemeFeature", py::arithmetic())
      .value("PKE", PKESchemeFeature::PKE)
      .value("KEYSWITCH", PKESchemeFeature::KEYSWITCH)
      .value("PRE", PKESchemeFeature::PRE)
      .value("LEVELEDSHE", PKESchemeFeature::LEVELEDSHE)
      .value("ADVANCEDSHE", PKESchemeFeature::ADVANCEDSHE)
      .value("MULTIPARTY", PKESchemeFeature::MULTIPARTY)
      .value("FHE", PKESchemeFeature::FHE)
      .export_values();

  py::enum_<ScalingTechnique>(m, "ScalingTechnique", py::arithmetic())
      .value("FIXEDMANUAL", ScalingTechnique::FIXEDMANUAL)
      .value("FIXEDAUTO", ScalingTechnique::FIXEDAUTO)
      .value("FLEXIBLEAUTO", ScalingTechnique::FLEXIBLEAUTO)
      .value("NORESCALE", ScalingTechnique::NORESCALE)
      .export_values();

  py::enum_<SecurityLevel>(m, "SecurityLevel", py::arithmetic())
      .value("HEStd_128_classic", SecurityLevel::HEStd_128_classic)
      .value("HEStd_192_classic", SecurityLevel::HEStd_192_classic)
      .value("HEStd_256_classic", SecurityLevel::HEStd_256_classic)
      .value("HEStd_NotSet", SecurityLevel::HEStd_NotSet)
      .export_values();

  py::enum_<SecretKeyDist>(m, "SecretKeyDist", py::arithmetic())
      .value("GAUSSIAN", SecretKeyDist::GAUSSIAN)
      .value("UNIFORM_TERNARY", SecretKeyDist::UNIFORM_TERNARY)
      .value("SPARSE_TERNARY", SecretKeyDist::SPARSE_TERNARY)
      .export_values();

  py::class_<Params>(m, "Params")
        .def(py::init<>())
        .def("SetRingDim", &Params::SetRingDim)
        .def("SetSecurityLevel", &Params::SetSecurityLevel)
        .def("SetSecretKeyDist", &Params::SetSecretKeyDist)
        .def("SetScalingModSize", &Params::SetScalingModSize)
        .def("SetFirstModSize", &Params::SetFirstModSize)
        .def("SetScalingTechnique", &Params::SetScalingTechnique)
        .def("SetMultiplicativeDepth", &Params::SetMultiplicativeDepth);

  py::class_<CCParams<CryptoContextCKKSRNS>>(m, "CryptoParameters")
        .def(py::init<>())
        .def("SetRingDim", &CCParams<CryptoContextCKKSRNS>::SetRingDim)
        .def("SetSecurityLevel", &CCParams<CryptoContextCKKSRNS>::SetSecurityLevel)
        .def("SetSecretKeyDist", &CCParams<CryptoContextCKKSRNS>::SetSecretKeyDist)
        .def("SetScalingModSize", &CCParams<CryptoContextCKKSRNS>::SetScalingModSize)
        .def("SetFirstModSize", &CCParams<CryptoContextCKKSRNS>::SetFirstModSize)
        .def("SetMultiplicativeDepth", &CCParams<CryptoContextCKKSRNS>::SetMultiplicativeDepth)
        .def("GetBootstrapDepth", [](CCParams<CryptoContextCKKSRNS>& self, int levelsUsedBeforeBootstrap, SecretKeyDist secretKeyDist){
            uint32_t approxBootstrapDepth     = 8;
            std::vector<uint32_t> levelBudget = {4, 4};
            usint depth                       = levelsUsedBeforeBootstrap +
                        FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, levelBudget, secretKeyDist);
            return depth;
        });


  py::class_<CryptoContextImpl<DCRTPoly>,std::shared_ptr<CryptoContextImpl<DCRTPoly>>>(m, "CryptoContextImpl")
        .def(py::init<>())
        .def("Enable", py::overload_cast<PKESchemeFeature>(&CryptoContextImpl<DCRTPoly>::Enable))
        .def("GetRingDimension", &CryptoContextImpl<DCRTPoly>::GetRingDimension)
        .def("EvalBootstrapSetup", [](CryptoContextImpl<DCRTPoly> &self, vector<uint32_t> levelBudget){
            vector<uint32_t> dim1 = {0, 0};
            uint32_t slots = 0;
            uint32_t correctionFactor = 0;

            self.EvalBootstrapSetup(levelBudget, dim1, slots, correctionFactor);
        })
        .def("KeyGen", &CryptoContextImpl<DCRTPoly>::KeyGen)
	.def("EvalSumKeyGen", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PrivateKeyImpl<DCRTPoly>> sk){ 
	    self.EvalSumKeyGen(sk);
	    return true;
	})
        .def("EvalMultKeyGen", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PrivateKeyImpl<DCRTPoly>> sk){
            self.EvalMultKeyGen(sk);
            return true;
        })
        .def("EvalBootstrapKeyGen", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PrivateKeyImpl<DCRTPoly>> sk, uint32_t slots){
            self.EvalBootstrapKeyGen(sk, slots);
            return true;
        })
        .def("ReEncrypt", [](CryptoContextImpl<DCRTPoly> &self ,std::shared_ptr<CiphertextImpl<DCRTPoly>> ct ,std::shared_ptr<EvalKeyImpl<DCRTPoly>> evalkey){
	    return self.ReEncrypt(ct,evalkey);		
	})
	.def("ReKeyGen", [](CryptoContextImpl<DCRTPoly> &self, const std::shared_ptr<PrivateKeyImpl<DCRTPoly>> sk ,const std::shared_ptr<PublicKeyImpl<DCRTPoly>> pk){

	    return self.ReKeyGen(sk,pk);
	})
        //.def("EvalRotateKeyGen", &CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen)
        .def("EvalRotateKeyGen", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PrivateKeyImpl<DCRTPoly>> sk, vector<int32_t> slots){
            self.EvalRotateKeyGen(sk, slots);
            return true;
        })

        .def("MakeCKKSPackedPlaintext", [](CryptoContextImpl<DCRTPoly> &self,vector<double> slots){
	        return self.MakeCKKSPackedPlaintext(slots);
	})


        // .def("Encrypt", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PlaintextImpl> pt, std::shared_ptr<PublicKeyImpl<DCRTPoly>> pk){
        //     return self.Encrypt(pt, pk);
        // })

        .def("Encrypt", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PublicKeyImpl<DCRTPoly>> pk, std::shared_ptr<CKKSPackedEncoding> pt){
            return self.Encrypt(pk, pt);
        })

        //.def("ReEncrypt", &CryptoContextImpl<DCRTPoly>::ReEncrypt)
        .def("Decrypt", [](CryptoContextImpl<DCRTPoly>& self, std::shared_ptr<CiphertextImpl<DCRTPoly>> ct, PrivateKey<DCRTPoly> sk){
            Plaintext res_c;
            self.Decrypt(sk, ct, &res_c);
            return res_c;
        })
        
        .def("EvalAdd", [](CryptoContextImpl<DCRTPoly>& self, std::shared_ptr<CiphertextImpl<DCRTPoly>> c1, std::shared_ptr<CiphertextImpl<DCRTPoly>> c2){
            return self.EvalAdd(c1, c2);
        })

        .def("EvalSub", [](CryptoContextImpl<DCRTPoly>& self, std::shared_ptr<CiphertextImpl<DCRTPoly>> c1, std::shared_ptr<CiphertextImpl<DCRTPoly>> c2){
            return self.EvalSub(c1, c2);
        })

        .def("EvalMult", [](CryptoContextImpl<DCRTPoly>& self, std::shared_ptr<CiphertextImpl<DCRTPoly>> c1, double s){
            return self.EvalMult(c1, s);
        })

        .def("EvalMultAndRelinearize", [](CryptoContextImpl<DCRTPoly>& self, std::shared_ptr<CiphertextImpl<DCRTPoly>> c1, std::shared_ptr<CiphertextImpl<DCRTPoly>> c2){
            return self.EvalMultAndRelinearize(c1, c2);
        })

        .def("EvalRotate", [](CryptoContextImpl<DCRTPoly>& self, std::shared_ptr<CiphertextImpl<DCRTPoly>> c1, int num){
            return self.EvalRotate(c1, num);
        })

        .def("EvalBootstrap", [](CryptoContextImpl<DCRTPoly>& self, std::shared_ptr<CiphertextImpl<DCRTPoly>> c){
            return self.EvalBootstrap(c);
        })


	.def("ClearEvalMultKeys",[](CryptoContextImpl<DCRTPoly>& self){
			return self.ClearEvalMultKeys();
	})

	.def("SerializeEvalMultKey",[](CryptoContextImpl<DCRTPoly>& self, std::string& filename){
			std::ofstream multkeyF(filename, std::ios::out | std::ios::binary);
	    	if(!multkeyF.is_open()){
                std::cerr << "Cannot write from " << filename  << std::endl;
                std::exit(1);
            }
			if(!self.SerializeEvalMultKey(multkeyF,SerType::BINARY)){
				multkeyF.close();
				std::cerr << "Cannot serialize " << std::endl;
				std::exit(1);
				return false;
			}		
			else{
				multkeyF.close();
				return true;
			}	
		
			
	})

	.def("DeserializeEvalMultKey",[](CryptoContextImpl<DCRTPoly>& self, std::string& filename){
			std::ifstream multkeyIS(filename, std::ios::in | std::ios::binary);
			if(!multkeyIS.is_open()){
				std::cerr << "Cannot read from " << filename  << std::endl;
				std::exit(1);
			}
			if(!self.DeserializeEvalMultKey(multkeyIS,SerType::BINARY)){
                                multkeyIS.close();
                                std::cerr << "Cannot serialize " << std::endl;
                                std::exit(1);
                                return false;
                        }
                        else{
                                multkeyIS.close();
                                return true;
                        }
			
        })


	.def("ClearEvalSumKeys",[](CryptoContextImpl<DCRTPoly>& self){
            return self.ClearEvalSumKeys();
    })

        .def("SerializeEvalSumKey",[](CryptoContextImpl<DCRTPoly>& self, std::string& filename){
            std::ofstream sumkeyF(filename, std::ios::out | std::ios::binary);
            if(!sumkeyF.is_open()){
                    std::cerr << "Cannot write from " << filename  << std::endl;
                    std::exit(1);
            }
            if(!self.SerializeEvalSumKey(sumkeyF,SerType::BINARY)){
                    sumkeyF.close();
                    std::cerr << "Cannot serialize " << std::endl;
                    std::exit(1);
                    return false;
            }
            else{
                    sumkeyF.close();
                    return true;
            }


        })

        .def("DeserializeEvalSumKey",[](CryptoContextImpl<DCRTPoly>& self, std::string& filename){
            std::ifstream sumkeyIS(filename, std::ios::in | std::ios::binary);
            if(!sumkeyIS.is_open()){
                    std::cerr << "Cannot read from " << filename  << std::endl;
                    std::exit(1);
            }
            if(!self.DeserializeEvalSumKey(sumkeyIS,SerType::BINARY)){
                    sumkeyIS.close();
                    std::cerr << "Cannot serialize " << std::endl;
                    std::exit(1);
                    return false;
            }
            else{
                    sumkeyIS.close();
                    return true;
            }

        })

	.def("ClearEvalAutomorphismKeys",[](CryptoContextImpl<DCRTPoly>& self){
        return self.ClearEvalAutomorphismKeys();
    })

        .def("SerializeEvalAutomorphismKey",[](CryptoContextImpl<DCRTPoly>& self, std::string& filename){
            std::ofstream amkeyF(filename, std::ios::out | std::ios::binary);
            if(!amkeyF.is_open()){
                    std::cerr << "Cannot write from " << filename  << std::endl;
                    std::exit(1);
            }
            if(!self.SerializeEvalAutomorphismKey(amkeyF,SerType::BINARY)){
                    amkeyF.close();
                    std::cerr << "Cannot serialize " << std::endl;
                    std::exit(1);
                    return false;
            }
            else{
                    amkeyF.close();
                    return true;
            }


        })

        .def("DeserializeEvalAutomorphismKey",[](CryptoContextImpl<DCRTPoly>& self, std::string& filename){
            std::ifstream amkeyIS(filename, std::ios::in | std::ios::binary);
            if(!amkeyIS.is_open()){
                    std::cerr << "Cannot read from " << filename  << std::endl;
                    std::exit(1);
            }
            if(!self.DeserializeEvalAutomorphismKey(amkeyIS,SerType::BINARY)){
                    amkeyIS.close();
                    std::cerr << "Cannot serialize " << std::endl;
                    std::exit(1);
                    return false;
            }
            else{
                    amkeyIS.close();
                    return true;
            }

        });

    
    py::class_<CKKSPackedEncoding, std::shared_ptr<CKKSPackedEncoding>>(m, "CKKSPackedEncoding")
        .def(py::init<>())
        .def("SetLength", [](CKKSPackedEncoding& self, int length){
            self.SetLength(length);
            return true;
        })
    	.def("GetLength", [](CKKSPackedEncoding& self){
	    return self.GetLength();
	})
        .def("Print", [](CKKSPackedEncoding& self){
            cout << self << endl;
            return true;
        })

	.def("GetRealPackedValue",[](CKKSPackedEncoding& self){
	    return self.GetRealPackedValue();
	});
    
    py::class_<Plaintext>(m, "Plaintext")
        .def(py::init<>())
        .def("SetLength", [](Plaintext& self, int length){
            self->SetLength(length);
            return true;
        })
        .def("Print", [](Plaintext& self){
            cout << self << endl;
            return true;
        });

	//.def("GetCKKSPackedValue",[](Plaintext& self){
	//   return this->GetCKKSPackedValue();

	//});

    py::class_<Ciphertext<DCRTPoly>>(m, "Ciphertext")
        .def(py::init<>());

    py::class_<CiphertextImpl<DCRTPoly>, std::shared_ptr<CiphertextImpl<DCRTPoly>>>(m, "CiphertextImpl")
        .def(py::init<>());

    py::class_<KeyPair<DCRTPoly>>(m, "KeyPair")
        .def(py::init<>())
        .def("publicKey", [](KeyPair<DCRTPoly> &self){
            return self.publicKey;
        })
        .def("secretKey", [](KeyPair<DCRTPoly> &self){
            return self.secretKey;
        });

    py::class_<Key<DCRTPoly>>(m, "Key");

    py::class_<PublicKey<DCRTPoly>>(m, "PublicKey")
        .def(py::init<>());

    py::class_<PrivateKey<DCRTPoly>>(m, "PrivateKey")
        .def(py::init<>());
    
    py::class_<PublicKeyImpl<DCRTPoly>, std::shared_ptr<PublicKeyImpl<DCRTPoly>>>(m, "PublicKeyImpl")
        .def(py::init<>());

    py::class_<PrivateKeyImpl<DCRTPoly>, std::shared_ptr<PrivateKeyImpl<DCRTPoly>>>(m, "PrivateKeyImpl")
        .def(py::init<>());

    py::class_<EvalKeyImpl<DCRTPoly>, std::shared_ptr<EvalKeyImpl<DCRTPoly>>>(m, "EvalKeyImpl")
        .def(py::init<>());
    

}
