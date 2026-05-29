#pragma once

/**
 * @file EncryptedMatrix.h
 * @brief Inline helpers for textbook encrypted square-matrix multiplication.
 *
 * Contents: CiphertextMatrix alias, matrix validation, and O(n^3)
 * ciphertext-matrix multiplication routines.
 * Main usage: test or prototype matrix products where each matrix entry is a
 * separate CKKS ciphertext.
 * Depends on: common/Assert.h and core/Context.h.
 */

#include <string>
#include <utility>
#include <vector>

#include "common/Assert.h"
#include "core/Context.h"

namespace cheddar {

/**
 * @brief A square matrix whose entries are CKKS ciphertexts.
 *
 * Each ciphertext entry is expected to share the same level, scale, and slot
 * count so matrix multiplication can reuse the regular FHE add/multiply
 * operators safely.
 *
 * @tparam word uint32_t or uint64_t
 */
template <typename word>
using CiphertextMatrix = std::vector<std::vector<Ciphertext<word>>>;

namespace detail {

template <typename word>
void AssertValidSquareCiphertextMatrix(ConstContextPtr<word> context,
                                       const CiphertextMatrix<word> &matrix,
                                       int dimension,
                                       const std::string &name) {
  AssertTrue(static_cast<int>(matrix.size()) == dimension,
             name + " must contain " + std::to_string(dimension) + " rows");
  AssertTrue(static_cast<int>(matrix.front().size()) == dimension,
             name + " must be square");

  const auto &ref = matrix.front().front();
  AssertFalse(ref.HasRx(), name + " entries must be relinearized first");

  for (int row = 0; row < dimension; ++row) {
    AssertTrue(static_cast<int>(matrix.at(row).size()) == dimension,
               name + " must be square");
    for (int col = 0; col < dimension; ++col) {
      const auto &entry = matrix.at(row).at(col);
      AssertFalse(entry.HasRx(), name + " entries must be relinearized first");
      AssertSameNP(ref, entry);
      context->AssertSameScale(ref, entry);
      AssertTrue(entry.GetNumSlots() == ref.GetNumSlots(),
                 name + " entries must use the same number of slots");
    }
  }
}

}  // namespace detail

/**
 * @brief Multiply two encrypted square matrices in the textbook O(n^3) way.
 *
 * Matrices are multiplied entry-wise with Context::HMult and accumulated with
 * Context::Add:
 *   res[i][j] = sum_k lhs[i][k] * rhs[k][j]
 *
 * When `rescale` is true, every product term uses the merged
 * relinearize-and-rescale path, so the output entries land one level below the
 * inputs while preserving the input scale.
 *
 * @tparam word uint32_t or uint64_t
 * @param context CKKS context
 * @param res output square matrix
 * @param lhs left input square matrix
 * @param rhs right input square matrix
 * @param mult_key multiplication evaluation key
 * @param rescale whether to rescale after each ciphertext multiplication
 */
template <typename word>
void HMultSquareMatrices(ConstContextPtr<word> context,
                         CiphertextMatrix<word> &res,
                         const CiphertextMatrix<word> &lhs,
                         const CiphertextMatrix<word> &rhs,
                         const EvaluationKey<word> &mult_key,
                         bool rescale = true) {
  AssertTrue(context != nullptr, "HMultSquareMatrices requires a valid context");
  AssertTrue(!lhs.empty(),
             "HMultSquareMatrices requires matrices with positive dimension");

  int dimension = static_cast<int>(lhs.size());
  AssertTrue(static_cast<int>(rhs.size()) == dimension,
             "HMultSquareMatrices requires matrices with the same dimension");

  detail::AssertValidSquareCiphertextMatrix(context, lhs, dimension,
                                            "Left matrix");
  detail::AssertValidSquareCiphertextMatrix(context, rhs, dimension,
                                            "Right matrix");

  AssertSameNP(lhs.front().front(), rhs.front().front());
  context->AssertSameScale(lhs.front().front(), rhs.front().front());
  AssertTrue(lhs.front().front().GetNumSlots() == rhs.front().front().GetNumSlots(),
             "Input matrices must use the same number of slots");
  if (rescale) {
    int level = context->param_.NPToLevel(lhs.front().front().GetNP());
    AssertTrue(level > 0,
               "HMultSquareMatrices with rescale requires input level > 0");
  }

  CiphertextMatrix<word> tmp_res(dimension);
  for (auto &row : tmp_res) {
    row.resize(dimension);
  }

  for (int row = 0; row < dimension; ++row) {
    for (int col = 0; col < dimension; ++col) {
      Ciphertext<word> accum;
      bool is_first_term = true;

      for (int k = 0; k < dimension; ++k) {
        Ciphertext<word> product;
        context->HMult(product, lhs.at(row).at(k), rhs.at(k).at(col), mult_key,
                       rescale);

        if (is_first_term) {
          accum = std::move(product);
          is_first_term = false;
        } else {
          Ciphertext<word> next_accum;
          context->Add(next_accum, accum, product);
          accum = std::move(next_accum);
        }
      }

      tmp_res.at(row).at(col) = std::move(accum);
    }
  }

  res = std::move(tmp_res);
}

template <typename word>
void HMultSquareMatrices(ContextPtr<word> context,
                         CiphertextMatrix<word> &res,
                         const CiphertextMatrix<word> &lhs,
                         const CiphertextMatrix<word> &rhs,
                         const EvaluationKey<word> &mult_key,
                         bool rescale = true) {
  HMultSquareMatrices(ConstContextPtr<word>(context), res, lhs, rhs, mult_key,
                      rescale);
}

/**
 * @brief Convenience overload returning the encrypted result matrix.
 *
 * @tparam word uint32_t or uint64_t
 * @param context CKKS context
 * @param lhs left input square matrix
 * @param rhs right input square matrix
 * @param mult_key multiplication evaluation key
 * @param rescale whether to rescale after each ciphertext multiplication
 * @return CiphertextMatrix<word> encrypted matrix product
 */
template <typename word>
CiphertextMatrix<word> HMultSquareMatrices(
    ConstContextPtr<word> context, const CiphertextMatrix<word> &lhs,
    const CiphertextMatrix<word> &rhs,
    const EvaluationKey<word> &mult_key, bool rescale = true) {
  CiphertextMatrix<word> res;
  HMultSquareMatrices(context, res, lhs, rhs, mult_key, rescale);
  return res;
}

template <typename word>
CiphertextMatrix<word> HMultSquareMatrices(
    ContextPtr<word> context, const CiphertextMatrix<word> &lhs,
    const CiphertextMatrix<word> &rhs,
    const EvaluationKey<word> &mult_key, bool rescale = true) {
  return HMultSquareMatrices(ConstContextPtr<word>(context), lhs, rhs,
                             mult_key, rescale);
}

}  // namespace cheddar
