package jwk

import cats.effect.{Blocker, IO}
import jwk.Jwk.EllipticCurve.Curve.P256
import org.scalatest.funsuite.AsyncFunSuite

class GeneratorTest extends AsyncFunSuite {
  implicit val cs = IO.contextShift(executionContext)

  test("gen rsa") {
    Blocker[IO]
      .use { blocker =>
        implicit val value = Entropy.default[IO](blocker)
        val id             = Jwk.Id("keyId")
        Generator.RSA.generate[IO](id).map { rsa =>
          assert(rsa.id === id)
        }

      }
      .unsafeToFuture()

  }
  test("gen ec") {
    Blocker[IO]
      .use { blocker =>
        implicit val value = Entropy.default[IO](blocker)
        val id             = Jwk.Id("keyId")
        Generator.EC.generate[IO](id, P256).map { ec =>
          assert(ec.id === id)
        }

      }
      .unsafeToFuture()

  }
}
