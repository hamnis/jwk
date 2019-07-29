package jwk

import org.scalatest._
import io.circe.jawn._

class JwkTest extends FunSuite {
  test("rsa key from RFC") {
    val json =
      """
        |{"kty":"RSA",
        | "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        | "e":"AQAB",
        | "use": "sign",
        | "alg":"RS256",
        | "kid":"2011-04-29"}
      """.stripMargin

    val value = decode[JWKPublicKey.RSA](json)
    assert(value.isRight)
    println(value.map(_.publicKey))
  }

  test("Elliptic Curve from RFC") {
    val json =
      """
        |{"kty":"EC",
        | "crv":"P-256",
        | "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        | "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
        | "use":"enc",
        | "kid":"1"}
      """.stripMargin

    val value = decode[JWKPublicKey.EC](json)
    println(value)
    assert(value.isRight)
    println(value.map(_.publicKey))
  }
}
