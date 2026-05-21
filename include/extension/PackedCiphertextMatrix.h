#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "common/Assert.h"
#include "common/CommonUtils.h"
#include "core/Context.h"
#include "core/EvkMap.h"
#include "core/EvkRequest.h"

namespace cheddar {

namespace detail {

inline std::vector<Complex> FlattenSquareMatrixRowMajor(
    const std::vector<std::vector<double>> &matrix) {
  AssertFalse(matrix.empty(), "Matrix must be non-empty");
  int n = static_cast<int>(matrix.size());
  std::vector<Complex> flat;
  flat.reserve(n * n);
  for (int row = 0; row < n; ++row) {
    AssertTrue(static_cast<int>(matrix.at(row).size()) == n,
               "Matrix must be square");
    for (int col = 0; col < n; ++col) {
      flat.emplace_back(matrix.at(row).at(col), 0.0);
    }
  }
  return flat;
}

inline std::vector<std::vector<Complex>> ReshapeFlatToSquareMatrixRowMajor(
    const std::vector<Complex> &flat, int dimension) {
  AssertTrue(dimension > 0, "Matrix dimension must be positive");
  AssertTrue(static_cast<int>(flat.size()) >= dimension * dimension,
             "Input vector is too small to reshape into a square matrix");

  std::vector<std::vector<Complex>> matrix(
      dimension, std::vector<Complex>(dimension, Complex(0.0, 0.0)));
  for (int row = 0; row < dimension; ++row) {
    for (int col = 0; col < dimension; ++col) {
      matrix.at(row).at(col) = flat.at(row * dimension + col);
    }
  }
  return matrix;
}

template <typename word>
void ValidatePackedSquareCiphertext(ConstContextPtr<word> context,
                                    const Ciphertext<word> &ctxt,
                                    int dimension) {
  AssertTrue(context != nullptr,
             "Packed matrix helpers require a valid context");
  AssertTrue(dimension > 0, "Matrix dimension must be positive");
  AssertTrue(IsPowOfTwo(dimension),
             "Packed matrix helpers require power-of-two dimension");
  AssertTrue(dimension * dimension <= ctxt.GetNumSlots(),
             "Packed matrix does not fit in the ciphertext slots");
  AssertFalse(ctxt.HasRx(), "Packed matrix ciphertext must be relinearized");
}

template <typename word>
using RotationMaskMap = std::map<int, Plaintext<word>>;

template <typename word, typename PermFn>
RotationMaskMap<word> BuildPermutationMasks(ConstContextPtr<word> context,
                                            int dimension, int level,
                                            PermFn perm_fn) {
  int num_slots = dimension * dimension;
  AssertTrue(IsPowOfTwo(num_slots),
             "Packed matrix helpers require power-of-two flattened size");

  std::map<int, std::vector<Complex>> grouped_masks;
  for (int dst = 0; dst < num_slots; ++dst) {
    int src = perm_fn(dst);
    AssertTrue(src >= 0 && src < num_slots,
               "Permutation source index out of range");
    int rot = (src - dst + num_slots) % num_slots;
    if (grouped_masks.find(rot) == grouped_masks.end()) {
      grouped_masks.try_emplace(rot, num_slots, Complex(0.0, 0.0));
    }
    grouped_masks.at(rot).at(dst) = Complex(1.0, 0.0);
  }

  RotationMaskMap<word> compiled;
  for (auto &[rot, mask] : grouped_masks) {
    compiled.try_emplace(rot, Plaintext<word>());
    context->encoder_.Encode(compiled.at(rot), level, 1.0, mask);
  }
  return compiled;
}

template <typename word>
void ApplyRotationMasks(ConstContextPtr<word> context, Ciphertext<word> &res,
                        const Ciphertext<word> &input,
                        const RotationMaskMap<word> &rotation_masks,
                        const EvkMap<word> &evk_map) {
  AssertFalse(rotation_masks.empty(),
              "ApplyRotationMasks requires at least one rotation term");

  bool first = true;
  Ciphertext<word> accum;
  for (const auto &[rot, mask] : rotation_masks) {
    AssertSameNP(input, mask);

    const Ciphertext<word> *operand = &input;
    Ciphertext<word> rotated;
    if (rot != 0) {
      context->HRot(rotated, input, evk_map.GetRotationKey(rot), rot);
      operand = &rotated;
    }

    Ciphertext<word> term;
    context->Mult(term, *operand, mask);
    if (first) {
      accum = std::move(term);
      first = false;
    } else {
      Ciphertext<word> next;
      context->Add(next, accum, term);
      accum = std::move(next);
    }
  }
  res = std::move(accum);
}

}  // namespace detail

/**
 * @brief Helper for CKKS square matrices packed row-major into a single
 * ciphertext.
 *
 * The layout is:
 *   slot[row * n + col] = matrix[row][col]
 *
 * Matrix multiplication follows the same algorithm as the referenced backend:
 * 1. Diagonalize the left operand with sigma
 * 2. Diagonalize the right operand with tau
 * 3. Rotate the two diagonalized ciphertexts along columns / rows
 * 4. Multiply the aligned terms and accumulate
 *
 * Internally, each permutation matrix is realized as a sum of slot rotations
 * gated by plaintext 0/1 masks encoded at scale 1. This preserves the input
 * ciphertext scale through diagonalization, so the final ct-ct multiplies can
 * use the regular HMult path.
 *
 * @tparam word uint32_t or uint64_t
 */
template <typename word>
class PackedCiphertextMatrixMultiplier {
 private:
  using Ct = Ciphertext<word>;
  using RotationMaskMap = detail::RotationMaskMap<word>;

  int dimension_;
  int ct_level_;
  int num_slots_;
  RotationMaskMap sigma_masks_;
  RotationMaskMap tau_masks_;
  std::vector<RotationMaskMap> col_rot_masks_;
  std::vector<int> row_rot_amounts_;

 public:
  PackedCiphertextMatrixMultiplier(ConstContextPtr<word> context,
                                   int dimension, int ct_level)
      : dimension_{dimension},
        ct_level_{ct_level},
        num_slots_{dimension * dimension} {
    AssertTrue(context != nullptr,
               "PackedCiphertextMatrixMultiplier requires a valid context");
    AssertTrue(dimension_ > 0, "Matrix dimension must be positive");
    AssertTrue(IsPowOfTwo(dimension_),
               "PackedCiphertextMatrixMultiplier requires power-of-two dimension");
    AssertTrue(ct_level_ > 0,
               "Packed ct-ct matrix multiply requires ct_level > 0");

    sigma_masks_ = detail::BuildPermutationMasks<word>(
        context, dimension_, ct_level_, [this](int dst) {
          int row = dst / dimension_;
          int col = dst % dimension_;
          return row * dimension_ + ((row + col) % dimension_);
        });
    tau_masks_ = detail::BuildPermutationMasks<word>(
        context, dimension_, ct_level_, [this](int dst) {
          int row = dst / dimension_;
          int col = dst % dimension_;
          return ((row + col) % dimension_) * dimension_ + col;
        });

    col_rot_masks_.resize(dimension_);
    row_rot_amounts_.resize(dimension_, 0);
    for (int k = 1; k < dimension_; ++k) {
      col_rot_masks_.at(k) = detail::BuildPermutationMasks<word>(
          context, dimension_, ct_level_, [this, k](int dst) {
            int row = dst / dimension_;
            int col = dst % dimension_;
            return row * dimension_ + ((col - k + dimension_) % dimension_);
          });
      row_rot_amounts_.at(k) =
          (num_slots_ - ((k * dimension_) % num_slots_)) % num_slots_;
    }
  }

  int GetDimension() const { return dimension_; }

  void AddRequiredRotations(EvkRequest &req) const {
    for (const auto &[rot, _] : sigma_masks_) {
      if (rot != 0) req.AddRequest(rot, ct_level_);
    }
    for (const auto &[rot, _] : tau_masks_) {
      if (rot != 0) req.AddRequest(rot, ct_level_);
    }
    for (int k = 1; k < dimension_; ++k) {
      for (const auto &[rot, _] : col_rot_masks_.at(k)) {
        if (rot != 0) req.AddRequest(rot, ct_level_);
      }
      if (row_rot_amounts_.at(k) != 0) {
        req.AddRequest(row_rot_amounts_.at(k), ct_level_);
      }
    }
  }

  std::vector<Complex> Flatten(
      const std::vector<std::vector<double>> &matrix) const {
    AssertTrue(static_cast<int>(matrix.size()) == dimension_,
               "Matrix dimension mismatch");
    return detail::FlattenSquareMatrixRowMajor(matrix);
  }

  std::vector<std::vector<Complex>> Reshape(
      const std::vector<Complex> &flat) const {
    return detail::ReshapeFlatToSquareMatrixRowMajor(flat, dimension_);
  }

  void Multiply(ConstContextPtr<word> context, Ct &res, const Ct &lhs,
                const Ct &rhs, const EvkMap<word> &evk_map,
                const EvaluationKey<word> &mult_key,
                bool rescale = true) const {
    detail::ValidatePackedSquareCiphertext(context, lhs, dimension_);
    detail::ValidatePackedSquareCiphertext(context, rhs, dimension_);
    AssertSameNP(lhs, rhs);
    context->AssertSameScale(lhs, rhs);
    AssertTrue(context->param_.NPToLevel(lhs.GetNP()) == ct_level_,
               "Packed matrix multiplier input level mismatch");
    AssertTrue(context->param_.NPToLevel(rhs.GetNP()) == ct_level_,
               "Packed matrix multiplier input level mismatch");

    Ct diag_lhs, diag_rhs;
    detail::ApplyRotationMasks(context, diag_lhs, lhs, sigma_masks_, evk_map);
    detail::ApplyRotationMasks(context, diag_rhs, rhs, tau_masks_, evk_map);

    AssertSameNP(diag_lhs, diag_rhs);
    context->AssertSameScale(diag_lhs, diag_rhs);

    Ct accum;
    bool first = true;
    for (int k = 0; k < dimension_; ++k) {
      const Ct *lhs_term = &diag_lhs;
      const Ct *rhs_term = &diag_rhs;
      Ct lhs_rot, rhs_rot;

      if (k != 0) {
        detail::ApplyRotationMasks(context, lhs_rot, diag_lhs,
                                   col_rot_masks_.at(k), evk_map);
        context->HRot(rhs_rot, diag_rhs,
                      evk_map.GetRotationKey(row_rot_amounts_.at(k)),
                      row_rot_amounts_.at(k));
        lhs_term = &lhs_rot;
        rhs_term = &rhs_rot;
      }

      Ct product;
      context->HMult(product, *lhs_term, *rhs_term, mult_key, rescale);
      if (first) {
        accum = std::move(product);
        first = false;
      } else {
        Ct next;
        context->Add(next, accum, product);
        accum = std::move(next);
      }
    }

    res = std::move(accum);
  }

  Ct Multiply(ConstContextPtr<word> context, const Ct &lhs, const Ct &rhs,
              const EvkMap<word> &evk_map,
              const EvaluationKey<word> &mult_key,
              bool rescale = true) const {
    Ct res;
    Multiply(context, res, lhs, rhs, evk_map, mult_key, rescale);
    return res;
  }
};

template <typename word>
inline std::vector<Complex> EncodePackedSquareMatrixRowMajor(
    const std::vector<std::vector<double>> &matrix) {
  return detail::FlattenSquareMatrixRowMajor(matrix);
}

inline std::vector<std::vector<Complex>> DecodePackedSquareMatrixRowMajor(
    const std::vector<Complex> &flat, int dimension) {
  return detail::ReshapeFlatToSquareMatrixRowMajor(flat, dimension);
}

}  // namespace cheddar
