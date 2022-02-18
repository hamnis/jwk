package jwk

import cats.effect.IO
import cats.effect.unsafe.IORuntime
import jwk.Jwk.EllipticCurve.Curve.P256
import org.scalatest.funsuite.AsyncFunSuite

class GeneratorTest extends AsyncFunSuite {
  implicit val entropy: Entropy[IO] = Entropy.default[IO]()
  implicit val ioRuntime: IORuntime = IORuntime.global

  test("gen rsa") {
    val id = Jwk.Id("keyId")
    Generator.RSA
      .generate[IO](id)
      .map { rsa =>
        assert(rsa.id === id)
      }
      .unsafeToFuture()
  }
  test("gen ec") {
    val id = Jwk.Id("keyId")
    Generator.EC
      .generate[IO](id, P256)
      .map { ec =>
        assert(ec.id === id)
      }
      .unsafeToFuture()

  }
}
