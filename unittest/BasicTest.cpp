#undef ENABLE_EXTENSION

#include <chrono>

#include "Testbed.h"
#include "extension/EncryptedMatrix.h"
#include "extension/PackedCiphertextMatrix.h"

static constexpr int warm_up = 5;
using word = uint32_t;

TEST_P(Testbed32, EncodeDecode) {
  std::cout << "Encode and Decode functions exist for test purposes and their "
               "performance is not a priority."
            << std::endl;
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1;
    GenerateRandomMessage(msg1);

    Plaintext<word> pt1;
    Encode(pt1, msg1, level);

    std::vector<Complex> res;
    Decode(res, pt1);
    CompareMessages(msg1, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, EncodeEncryptDecryptDecode) {
  std::cout << "Encode, Encrypt, Decrypt and Decode functions exist for test "
               "purposes and their performance is not a priority."
            << std::endl;
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1;
    GenerateRandomMessage(msg1);

    Ciphertext<word> ct1;
    EncodeAndEncrypt(ct1, msg1, level);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct1);
    CompareMessages(msg1, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtAddCt) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] + msg2[i]);
    }
    Ciphertext<word> ct1, ct2;
    Ciphertext<word> ct_res;

    std::string name = "CtAddCt at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      EncodeAndEncrypt(ct2, msg2, level);
    };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Add(ct_res, ct1, ct2);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtAddPt) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] + msg2[i]);
    }
    Ciphertext<word> ct1;
    Plaintext<word> pt2;
    Ciphertext<word> ct_res;

    std::string name = "CtAddPt at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      Encode(pt2, msg2, level);
    };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Add(ct_res, ct1, pt2);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtAddConst) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    double const_value = msg2[0].real();
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] + const_value);
    }
    Ciphertext<word> ct1;
    Constant<word> const2;
    Ciphertext<word> ct_res;

    std::string name = "CtAddConst at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      EncodeConstant(const2, const_value, level);
    };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Add(ct_res, ct1, const2);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtSubCt) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] - msg2[i]);
    }
    Ciphertext<word> ct1, ct2;
    Ciphertext<word> ct_res;

    std::string name = "CtSubCt at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      EncodeAndEncrypt(ct2, msg2, level);
    };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Sub(ct_res, ct1, ct2);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtSubPt) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] - msg2[i]);
    }
    Ciphertext<word> ct1;
    Plaintext<word> pt2;
    Ciphertext<word> ct_res;

    std::string name = "CtSubPt at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      Encode(pt2, msg2, level);
    };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Sub(ct_res, ct1, pt2);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtSubConst) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    double const_value = msg2[0].real();
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] - const_value);
    }
    Ciphertext<word> ct1;
    Constant<word> const2;
    Ciphertext<word> ct_res;

    std::string name = "CtSubConst at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      EncodeConstant(const2, const_value, level);
    };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Sub(ct_res, ct1, const2);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, NegCt) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(-msg1[i]);
    }
    Ciphertext<word> ct1;
    Ciphertext<word> ct_res;

    std::string name = "NegCt at level" + std::to_string(level);
    auto prepare_cts = [&]() { EncodeAndEncrypt(ct1, msg1, level); };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Neg(ct_res, ct1);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtMultPt) {
  for (int level = 1; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] * msg2[i]);
    }
    Ciphertext<word> ct1;
    Plaintext<word> pt2;
    Ciphertext<word> ct_res;

    std::string name =
        "CtMultPt (w/o rescaling) at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      Encode(pt2, msg2, level);
    };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Mult(ct_res, ct1, pt2);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtMultConst) {
  for (int level = 1; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    double const_value = msg2[0].real();
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] * const_value);
    }
    Ciphertext<word> ct1;
    Constant<word> const2;
    Ciphertext<word> ct_res;

    std::string name =
        "CtMultConst (w/o rescaling) at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      EncodeConstant(const2, const_value, level);
    };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->Mult(ct_res, ct1, const2);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, CtMultImaginaryUnit) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(Complex(-msg1[i].imag(), msg1[i].real()));
    }
    Ciphertext<word> ct1;
    Ciphertext<word> ct_res;

    std::string name = "CtMultImaginaryUnit at level" + std::to_string(level);
    auto prepare_cts = [&]() { EncodeAndEncrypt(ct1, msg1, level); };

    __ProfileStart(name, warm_up, prepare_cts());
    context_->MultImaginaryUnit(ct_res, ct1);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, HMult) {
  for (int level = 1; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1, msg2;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    GenerateRandomMessage(msg2);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[i] * msg2[i]);
    }
    Ciphertext<word> ct1, ct2;
    Ciphertext<word> ct_res, ct_tmp;

    // Merged case;
    std::string name =
        "HMult(tensor + merged relin-rescale) at level" + std::to_string(level);
    auto prepare_cts = [&]() {
      EncodeAndEncrypt(ct1, msg1, level);
      EncodeAndEncrypt(ct2, msg2, level);
    };
    __ProfileStart(name, warm_up, prepare_cts(););
    context_->HMult(ct_res, ct1, ct2, interface_->GetMultiplicationKey(), true);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);

    // Non-merged case;
    name = "HMult(tensor + relinearize) at level" + std::to_string(level);
    __ProfileStart(name, warm_up, prepare_cts(););
    context_->HMult(ct_tmp, ct1, ct2, interface_->GetMultiplicationKey(),
                    false);
    __ProfileEnd(name);

    DecryptAndDecode(res, ct_tmp);
    CompareMessages(true_res, res, level == param_->max_level_);

    name = "Rescale at level" + std::to_string(level);
    __ProfileStart(name, warm_up,
                   context_->HMult(ct_tmp, ct1, ct2,
                                   interface_->GetMultiplicationKey(), false););
    context_->Rescale(ct_res, ct_tmp);
    __ProfileEnd(name);

    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, HRot) {
  int num_slots = (1 << log_degree_) / 2;
  word test_rot_dist = 1234;
  interface_->PrepareRotationKey(test_rot_dist, param_->max_level_);

  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(msg1[(i + test_rot_dist) % num_slots]);
    }
    Ciphertext<word> ct1, ct_res;
    std::string name = "HRot at level" + std::to_string(level);
    __ProfileStart(name, warm_up, EncodeAndEncrypt(ct1, msg1, level););
    context_->HRot(ct_res, ct1, interface_->GetRotationKey(test_rot_dist),
                   test_rot_dist);
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, HConj) {
  for (int level = 0; level <= param_->max_level_; level++) {
    std::vector<Complex> msg1;
    std::vector<Complex> true_res;
    GenerateRandomMessage(msg1);
    for (int i = 0; i < static_cast<int>(msg1.size()); i++) {
      true_res.push_back(std::conj(msg1[i]));
    }
    Ciphertext<word> ct1, ct_res;
    std::string name = "HConj at level" + std::to_string(level);
    __ProfileStart(name, warm_up, EncodeAndEncrypt(ct1, msg1, level););
    context_->HConj(ct_res, ct1, interface_->GetConjugationKey());
    __ProfileEnd(name);

    std::vector<Complex> res;
    DecryptAndDecode(res, ct_res);
    CompareMessages(true_res, res, level == param_->max_level_);
  }
}

TEST_P(Testbed32, EncryptedSquareMatrixHMult) {
  constexpr int dimension = 2;
  const int level = param_->max_level_;

  auto make_scalar_message = [](double value) {
    return std::vector<Complex>{Complex(value, 0.0)};
  };

  std::vector<std::vector<double>> lhs_plain{
      {1.0, 2.0},
      {3.0, 4.0},
  };
  std::vector<std::vector<double>> rhs_plain{
      {5.0, 6.0},
      {7.0, 8.0},
  };
  std::vector<std::vector<double>> expected{
      {19.0, 22.0},
      {43.0, 50.0},
  };

  CiphertextMatrix<word> lhs_ct(dimension);
  CiphertextMatrix<word> rhs_ct(dimension);
  auto prepare_cts = [&]() {
    for (int row = 0; row < dimension; ++row) {
      lhs_ct[row].resize(dimension);
      rhs_ct[row].resize(dimension);
      for (int col = 0; col < dimension; ++col) {
        EncodeAndEncrypt(lhs_ct[row][col],
                         make_scalar_message(lhs_plain[row][col]), level);
        EncodeAndEncrypt(rhs_ct[row][col],
                         make_scalar_message(rhs_plain[row][col]), level);
      }
    }
  };

  CiphertextMatrix<word> res_ct;
  std::string name = "EncryptedSquareMatrixHMult (" +
                     std::to_string(dimension) + "x" +
                     std::to_string(dimension) + ") at level " +
                     std::to_string(level);
  __ProfileStart(name, warm_up, prepare_cts());
  res_ct = HMultSquareMatrices(context_, lhs_ct, rhs_ct,
                               interface_->GetMultiplicationKey(), true);
  __ProfileEnd(name);

  ASSERT_EQ(static_cast<int>(res_ct.size()), dimension);
  for (int row = 0; row < dimension; ++row) {
    ASSERT_EQ(static_cast<int>(res_ct[row].size()), dimension);
    for (int col = 0; col < dimension; ++col) {
      EXPECT_EQ(param_->NPToLevel(res_ct[row][col].GetNP()), level - 1);
      std::vector<Complex> decoded;
      DecryptAndDecode(decoded, res_ct[row][col]);
      ASSERT_FALSE(decoded.empty());
      EXPECT_NEAR(decoded[0].real(), expected[row][col], max_error_);
      EXPECT_NEAR(decoded[0].imag(), 0.0, max_error_);
    }
  }
}

TEST_P(Testbed32, PackedCiphertextSquareMatrixHMult) {
  constexpr int dimension = 4;
  const int level = param_->max_level_;

  PackedCiphertextMatrixMultiplier<word> packed_multiplier(context_, dimension,
                                                           level);
  EvkRequest rot_req;
  packed_multiplier.AddRequiredRotations(rot_req);
  interface_->PrepareRotationKey(rot_req);

  std::vector<std::vector<double>> lhs_plain{
      {1.0, 2.0, 3.0, 4.0},
      {5.0, 6.0, 7.0, 8.0},
      {9.0, 10.0, 11.0, 12.0},
      {13.0, 14.0, 15.0, 16.0},
  };
  std::vector<std::vector<double>> rhs_plain{
      {17.0, 18.0, 19.0, 20.0},
      {21.0, 22.0, 23.0, 24.0},
      {25.0, 26.0, 27.0, 28.0},
      {29.0, 30.0, 31.0, 32.0},
  };

  std::vector<std::vector<double>> expected(
      dimension, std::vector<double>(dimension, 0.0));
  for (int row = 0; row < dimension; ++row) {
    for (int col = 0; col < dimension; ++col) {
      for (int k = 0; k < dimension; ++k) {
        expected.at(row).at(col) +=
            lhs_plain.at(row).at(k) * rhs_plain.at(k).at(col);
      }
    }
  }

  std::vector<Complex> lhs_msg = packed_multiplier.Flatten(lhs_plain);
  std::vector<Complex> rhs_msg = packed_multiplier.Flatten(rhs_plain);

  Ciphertext<word> lhs_ct, rhs_ct, res_ct;
  auto prepare_cts = [&]() {
    EncodeAndEncrypt(lhs_ct, lhs_msg, level);
    EncodeAndEncrypt(rhs_ct, rhs_msg, level);
  };

  std::string name = "PackedCiphertextSquareMatrixHMult (" +
                     std::to_string(dimension) + "x" +
                     std::to_string(dimension) + ") at level " +
                     std::to_string(level);
  __ProfileStart(name, warm_up, prepare_cts());
  packed_multiplier.Multiply(context_, res_ct, lhs_ct, rhs_ct,
                             interface_->GetEvkMap(),
                             interface_->GetMultiplicationKey(), true);
  __ProfileEnd(name);

  EXPECT_EQ(param_->NPToLevel(res_ct.GetNP()), level - 1);

  std::vector<Complex> decoded_flat;
  DecryptAndDecode(decoded_flat, res_ct);
  auto decoded = packed_multiplier.Reshape(decoded_flat);

  for (int row = 0; row < dimension; ++row) {
    for (int col = 0; col < dimension; ++col) {
      EXPECT_NEAR(decoded.at(row).at(col).real(), expected.at(row).at(col),
                  max_error_);
      EXPECT_NEAR(decoded.at(row).at(col).imag(), 0.0, max_error_);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    Cheddar, Testbed32,
    testing::Values("bootparam_30.json", "bootparam_35.json",
                    "bootparam_40.json"),
    [](const testing::TestParamInfo<Testbed32::ParamType> &info) {
      std::string param_name = info.param;
      std::replace(param_name.begin(), param_name.end(), '.', '_');
      return param_name;
    });
