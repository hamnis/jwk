package jwk

sealed abstract class KeyOp(val value: String)

object KeyOp {
  case object Sign               extends KeyOp("sign")
  case object Verify             extends KeyOp("verify")
  case object Encrypt            extends KeyOp("encrypt")
  case object Decrypt            extends KeyOp("decrypt")
  case object WrapKey            extends KeyOp("wrapKey")
  case object UnwrapKey          extends KeyOp("unwrapKey")
  case object DeriveKey          extends KeyOp("deriveKey")
  case object DeriveBits         extends KeyOp("deriveBits")
  case class Other(name: String) extends KeyOp(name)

  private val values: List[KeyOp] = List(Sign, Verify, Encrypt, Decrypt, WrapKey, UnwrapKey, DeriveKey, DeriveBits)

  def apply(s: String): KeyOp =
    values.find(_.value == s).getOrElse(Other(s))
}
