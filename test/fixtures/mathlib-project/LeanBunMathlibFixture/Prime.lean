import Mathlib.Data.Nat.Prime.Basic

namespace LeanBunMathlibFixture

theorem seven_is_prime : Nat.Prime 7 := by
  decide

theorem eleven_is_prime : Nat.Prime 11 := by
  decide

theorem seven_and_eleven_are_distinct : (7 : Nat) ≠ 11 := by
  decide

end LeanBunMathlibFixture
