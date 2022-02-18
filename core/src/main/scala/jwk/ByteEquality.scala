package jwk

import scodec.bits.ByteVector

private[jwk] object ByteEquality {

  /** Constant-time byte comparison.
    *
    * @param b a byte
    * @param c a byte
    * @return 1 if b and c are equal, 0 otherwise.
    */
  def equal(b: Int, c: Int): Int = {
    var result = 0
    val xor = b ^ c
    for (i <- 0 until 8)
      result |= xor >> i
    (result ^ 0x01) & 0x01
  }

  /**
   * Constant-time byte[] comparison.
   *
   * @param b a byte[]
   * @param c a byte[]
   * @return 1 if b and c are equal, 0 otherwise.
   */
  def equal(b: Array[Byte], c: Array[Byte], length: Int): Int = {
    var result = 0
    for (i <- 0 until length)
      result |= b(i) ^ c(i)
    equal(result, 0)
  }

  def equal(a: ByteVector, b: ByteVector): Boolean = {
    if (a.size == b.size) return equal(a.toArray, b.toArray, a.size.toInt) == 1
    false
  }
}
