/**
 * @file EvkMap.cpp
 * @brief Lookup helpers for evaluation-key maps.
 *
 * Contents: checked accessors for rotation, multiplication, conjugation,
 * dense-to-sparse, and sparse-to-dense evaluation keys.
 * Main usage: centralize key-index conventions and validation before
 * homomorphic key switching operations.
 * Depends on: core/EvkMap.h and common/Assert.h.
 */

#include "core/EvkMap.h"

#include "common/Assert.h"

namespace cheddar {

template <typename word>
const EvaluationKey<word> &EvkMap<word>::GetEvk(int key_idx) const {
  auto it = this->find(key_idx);
  AssertTrue(it != this->end(),
             "GetEvk: Key not found for index " + std::to_string(key_idx));
  return it->second;
}

template <typename word>
const EvaluationKey<word> &EvkMap<word>::GetRotationKey(int rot_idx) const {
  AssertTrue(rot_idx > 0, "GetRotationKey: Invalid rotation index");
  return GetEvk(rot_idx);
}

template <typename word>
const EvaluationKey<word> &EvkMap<word>::GetMultiplicationKey() const {
  return GetEvk(kMultiplicationKeyIndex);
}

template <typename word>
const EvaluationKey<word> &EvkMap<word>::GetConjugationKey() const {
  return GetEvk(kConjugationKeyIndex);
}

template <typename word>
const EvaluationKey<word> &EvkMap<word>::GetDenseToSparseKey() const {
  return GetEvk(kDenseToSparseKeyIndex);
}

template <typename word>
const EvaluationKey<word> &EvkMap<word>::GetSparseToDenseKey() const {
  return GetEvk(kSparseToDenseKeyIndex);
}

template class EvkMap<uint32_t>;
template class EvkMap<uint64_t>;

}  // namespace cheddar
