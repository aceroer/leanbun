namespace LeanBunLakeFixture

def double (value : Nat) : Nat := value + value

theorem double_zero : double 0 = 0 := by
  rfl

theorem double_add (left right : Nat) :
    double (left + right) = double left + double right := by
  simp [double, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm]

end LeanBunLakeFixture
