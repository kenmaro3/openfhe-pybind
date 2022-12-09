#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <memory>
#include "stdio.h"
#include <vector>

#include "openfhe.h"

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
  m.def("generate_context_from_parameters", &generate_context_from_parameters);

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


  py::class_<CryptoContextImpl<DCRTPoly>>(m, "CryptoContextImpl")
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
        .def("EvalMultKeyGen", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PrivateKeyImpl<DCRTPoly>> sk){
            self.EvalMultKeyGen(sk);
            return true;
        })
        .def("EvalBootstrapKeyGen", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PrivateKeyImpl<DCRTPoly>> sk, uint32_t slots){
            self.EvalBootstrapKeyGen(sk, slots);
            return true;
        })
        .def("ReEncrypt", &CryptoContextImpl<DCRTPoly>::ReEncrypt)
        // .def("ReKeyGen", py::overload_cast<PrivateKey<DCRTPoly>, PublicKey<DCRTPoly>>(&CryptoContextImpl<DCRTPoly>::ReKeyGen))
        //.def("EvalRotateKeyGen", &CryptoContextImpl<DCRTPoly>::EvalRotateKeyGen)
        .def("EvalRotateKeyGen", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PrivateKeyImpl<DCRTPoly>> sk, vector<int32_t> slots){
            self.EvalRotateKeyGen(sk, slots);
            return true;
        })
        .def("MakeCKKSPackedPlaintext", &CryptoContextImpl<DCRTPoly>::MakeCKKSPackedPlaintextTmp)
        // .def("Encrypt", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PlaintextImpl> pt, std::shared_ptr<PublicKeyImpl<DCRTPoly>> pk){
        //     return self.Encrypt(pt, pk);
        // })

        .def("Encrypt", [](CryptoContextImpl<DCRTPoly> &self, std::shared_ptr<PublicKeyImpl<DCRTPoly>> pk, std::shared_ptr<CKKSPackedEncoding> pt){
            return self.Encrypt(pk, pt);
        })

        .def("ReEncrypt", &CryptoContextImpl<DCRTPoly>::ReEncrypt)
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
        });


        // .def("EvalMult", &CryptoContextImpl<DCRTPoly>::EvalMult)
        // .def("EvalMultAndRelinearize", &CryptoContextImpl<DCRTPoly>::EvalMultAndRelinearize)
        // .def("EvalRotate", &CryptoContextImpl<DCRTPoly>::EvalRotate)
        // .def("EvalBootstrap", &CryptoContextImpl<DCRTPoly>::EvalBootstrap);
    
    py::class_<CKKSPackedEncoding, std::shared_ptr<CKKSPackedEncoding>>(m, "CKKSPackedEncoding")
        .def(py::init<>())
        .def("SetLength", [](CKKSPackedEncoding& self, int length){
            self.SetLength(length);
            return true;
        })
        .def("Print", [](CKKSPackedEncoding& self){
            cout << self << endl;
            return true;
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
