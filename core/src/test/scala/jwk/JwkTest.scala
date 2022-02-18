package jwk

import io.circe.jawn._
import io.circe.syntax._
import jwk.circe._
import org.scalatest.funsuite.AnyFunSuite

class JwkTest extends AnyFunSuite {
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

    val value = decode[Jwk.RSA](json)
    assert(value.isRight)
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

    val value = decode[Jwk.EllipticCurve](json)
    assert(value.isRight)
  }

  test("With signature chain") {
    val json =
      """
      |{"kty":"RSA",
      | "use":"sig",
      | "kid":"1b94c",
      | "n":"vrjOfz9Ccdgx5nQudyhdoR17V-IubWMeOZCwX_jj0hgAsz2J_pqYW08PLbK_PdiVGKPrqzmDIsLI7sA25VEnHU1uCLNwBuUiCO11_-7dYbsr4iJmG0Qu2j8DsVyT1azpJC_NG84Ty5KKthuCaPod7iI7w0LK9orSMhBEwwZDCxTWq4aYWAchc8t-emd9qOvWtVMDC2BXksRngh6X5bUYLy6AyHKvj-nUy1wgzjYQDwHMTplCoLtU-o-8SNnZ1tmRoGE9uJkBLdh5gFENabWnU5m1ZqZPdwS-qo-meMvVfJb6jJVWRpl2SUtCnYG2C32qvbWbjZ_jBPD5eunqsIo1vQ",
      | "e":"AQAB",
      | "x5c":
      |  ["MIIDQjCCAiqgAwIBAgIGATz/FuLiMA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDAeFw0xMzAyMjEyMzI5MTVaFw0xODA4MTQyMjI5MTVaMGIxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDTzEPMA0GA1UEBxMGRGVudmVyMRwwGgYDVQQKExNQaW5nIElkZW50aXR5IENvcnAuMRcwFQYDVQQDEw5CcmlhbiBDYW1wYmVsbDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL64zn8/QnHYMeZ0LncoXaEde1fiLm1jHjmQsF/449IYALM9if6amFtPDy2yvz3YlRij66s5gyLCyO7ANuVRJx1NbgizcAblIgjtdf/u3WG7K+IiZhtELto/A7Fck9Ws6SQvzRvOE8uSirYbgmj6He4iO8NCyvaK0jIQRMMGQwsU1quGmFgHIXPLfnpnfajr1rVTAwtgV5LEZ4Iel+W1GC8ugMhyr4/p1MtcIM42EA8BzE6ZQqC7VPqPvEjZ2dbZkaBhPbiZAS3YeYBRDWm1p1OZtWamT3cEvqqPpnjL1XyW+oyVVkaZdklLQp2Btgt9qr21m42f4wTw+Xrp6rCKNb0CAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAh8zGlfSlcI0o3rYDPBB07aXNswb4ECNIKG0CETTUxmXl9KUL+9gGlqCz5iWLOgWsnrcKcY0vXPG9J1r9AqBNTqNgHq2G03X09266X5CpOe1 zFo+Owb1zxtp3PehFdfQJ610CDLEaS9V9Rqp17hCyybEpOGVwe8fnk+fbEL2Bo3UPGrpsHzUoaGpDftmWssZkhpBJKVMJyf/RuP2SmmaIzmnw9JiSlYhzo4tpzd5rFXhjRbg4zW9C+2qok+2+qDM1iJ684gPHMIY8aLWrdgQTxkumGmTqgawR+N5MDtdPTEQ0XfIBc2cJEUyMTY5MPvACWpkA6SdS4xSvdXK3IVfOWA=="]
      |}
      |""".stripMargin

    val Right(value) = decode[Jwk.RSA](json)
    assert(JwkParser.validate(value).isRight)
    val Right(viaJson) = value.asJson.as[Jwk.RSA]
    assert(JwkParser.validate(viaJson).isRight)
    assert(viaJson === value)
  }

  test("From auth0 should parse") {
    val json =
      """
        |{
        |  "alg": "RS256",
        |  "kty": "RSA",
        |  "use": "sig",
        |  "x5c": [
        |    "MIIDETCCAfmgAwIBAgIJALUn2x16sU0BMA0GCSqGSIb3DQEBCwUAMB8xHTAbBgNVBAMMFGV4YW1wbGUuZXUuYXV0aDAuY29tMB4XDTE1MDQyMzA3MTcyOVoXDTI4MTIzMDA3MTcyOVowHzEdMBsGA1UEAwwUZXhhbXBsZS5ldS5hdXRoMC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQColCyrzR24viQYf3gdHSrH1rCMS7wH3SOmzq5RRZeOxz6wcmTr8Jip/SQiS5QSsFfUoRk8PPbeafUhF+/NDwvCJXnUf8lTDeOAVRDM5hkfWnLZf8sBHYdAZXTps6Oz6Nq0MT4J/7cL43a1Q/UU8qwCYG652NPX2bPIAjfxq28MUJ47iz2EKg445MHpsuHU3MXqKApyLBlyUQL4VRw9xjlqkL45HTB2zCNuO4o8zQNE70jWQe8b4eauzLT5oeakUVTW5vGq5ryKE6T0vUERxYO/Bxzw+qfZ75IV9dQefUZ41WLB6PWP6OvzsRSEOGZR2LBMh3IfArhUwNxpkmTf4lZfAgMBAAGjUDBOMB0GA1UdDgQWBBShBM7FGFBWlZSI0AkqeI/tcZftQDAfBgNVHSMEGDAWgBShBM7FGFBWlZSI0AkqeI/tcZftQDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCOraDmW3eSauYY4Xdf81t7XgPiUiWaqHUOtLEFOVmpPlX8mHtcUpSHZwh2C52iLtFkBUq97r2AwmTArysTb+ZNsFotEaAxTe2f6dO8oV7lxjn5ApL3NZWVDXsO//F/kJTsA0AlGozdHedb/Xy90atY9IRBHqlY49QHJmiheSxy3QTuABEVfHShsbqhT22a/VOEWelwyJZyeQX03ysu6c9NqnWblU/9j/Ccg96VorL7bYN0dLgImdcZQFR8fjhGeV86n15C7ZvOE4cJyVdBc0er1IrEmx7oXG6YgxyBYMRL+DiIjZAftE6YjOuet2GQOSdGYPiYqn6Z7xLg4DPTaWEP"
        |  ],
        |  "n": "qJQsq80duL4kGH94HR0qx9awjEu8B90jps6uUUWXjsc-sHJk6_CYqf0kIkuUErBX1KEZPDz23mn1IRfvzQ8LwiV51H_JUw3jgFUQzOYZH1py2X_LAR2HQGV06bOjs-jatDE-Cf-3C-N2tUP1FPKsAmBuudjT19mzyAI38atvDFCeO4s9hCoOOOTB6bLh1NzF6igKciwZclEC-FUcPcY5apC-OR0wdswjbjuKPM0DRO9I1kHvG-Hmrsy0-aHmpFFU1ubxqua8ihOk9L1BEcWDvwcc8Pqn2e-SFfXUHn1GeNViwej1j-jr87EUhDhmUdiwTIdyHwK4VMDcaZJk3-JWXw",
        |  "e": "AQAB",
        |  "kid": "QUVGRUVENTEwNDUwODlFQjA1QzE0QkVBMUY5NDFFRjFBRjI5Mzc3MA",
        |  "x5t": "QUVGRUVENTEwNDUwODlFQjA1QzE0QkVBMUY5NDFFRjFBRjI5Mzc3MA"
        |}
        |""".stripMargin

    val Right(value) = decode[Jwk.RSA](json)
    assert(JwkParser.validate(value).isLeft)
  }

  test("RSA Private key from RFC") {
    val json =
      """
      |{"kty":"RSA",
      | "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      | "e":"AQAB",
      | "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
      | "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
      | "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
      | "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
      | "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
      | "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
      | "alg":"RS256",
      | "kid":"2011-04-29"
      |}
      |""".stripMargin
    val Right(value) = decode[Jwk.RSA](json)
    assert(value.privateKey.isDefined)
    assert(JwkParser.validate(value).isRight)
  }

  test("RSA Private key from Nimbus JOSE Website") {
    import io.circe.syntax._

    val json =
      """{
        |  "kty" : "RSA",
        |  "kid" : "cc34c0a0-bd5a-4a3c-a50d-a2a7db7643df",
        |  "use" : "sig",
        |  "n"   : "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
        |  "e"   : "AQAB",
        |  "d"   : "ksDmucdMJXkFGZxiomNHnroOZxe8AmDLDGO1vhs-POa5PZM7mtUPonxwjVmthmpbZzla-kg55OFfO7YcXhg-Hm2OWTKwm73_rLh3JavaHjvBqsVKuorX3V3RYkSro6HyYIzFJ1Ek7sLxbjDRcDOj4ievSX0oN9l-JZhaDYlPlci5uJsoqro_YrE0PRRWVhtGynd-_aWgQv1YzkfZuMD-hJtDi1Im2humOWxA4eZrFs9eG-whXcOvaSwO4sSGbS99ecQZHM2TcdXeAs1PvjVgQ_dKnZlGN3lTWoWfQP55Z7Tgt8Nf1q4ZAKd-NlMe-7iqCFfsnFwXjSiaOa2CRGZn-Q",
        |  "p"   : "4A5nU4ahEww7B65yuzmGeCUUi8ikWzv1C81pSyUKvKzu8CX41hp9J6oRaLGesKImYiuVQK47FhZ--wwfpRwHvSxtNU9qXb8ewo-BvadyO1eVrIk4tNV543QlSe7pQAoJGkxCia5rfznAE3InKF4JvIlchyqs0RQ8wx7lULqwnn0",
        |  "q"   : "ven83GM6SfrmO-TBHbjTk6JhP_3CMsIvmSdo4KrbQNvp4vHO3w1_0zJ3URkmkYGhz2tgPlfd7v1l2I6QkIh4Bumdj6FyFZEBpxjE4MpfdNVcNINvVj87cLyTRmIcaGxmfylY7QErP8GFA-k4UoH_eQmGKGK44TRzYj5hZYGWIC8",
        |  "dp"  : "lmmU_AG5SGxBhJqb8wxfNXDPJjf__i92BgJT2Vp4pskBbr5PGoyV0HbfUQVMnw977RONEurkR6O6gxZUeCclGt4kQlGZ-m0_XSWx13v9t9DIbheAtgVJ2mQyVDvK4m7aRYlEceFh0PsX8vYDS5o1txgPwb3oXkPTtrmbAGMUBpE",
        |  "dq"  : "mxRTU3QDyR2EnCv0Nl0TCF90oliJGAHR9HJmBe__EjuCBbwHfcT8OG3hWOv8vpzokQPRl5cQt3NckzX3fs6xlJN4Ai2Hh2zduKFVQ2p-AF2p6Yfahscjtq-GY9cB85NxLy2IXCC0PF--Sq9LOrTE9QV988SJy_yUrAjcZ5MmECk",
        |  "qi"  : "ldHXIrEmMZVaNwGzDF9WG8sHj2mOZmQpw9yrjLK9hAsmsNr5LTyqWAqJIYZSwPTYWhY4nu2O0EY9G9uYiqewXfCKw_UngrJt8Xwfq1Zruz0YY869zPN4GiE9-9rzdZB33RBw8kIOquY3MK74FMwCihYx_LiU2YTHkaoJ3ncvtvg"
        |}
        |""".stripMargin

    val Right(value) = JwkParser.parse(json)
    val decoded = value.asInstanceOf[Jwk.RSA]
    assert(decoded.privateKey.isDefined)
    val Right(value2) = JwkParser.parse(decoded.asJson.noSpaces)
    assert(decoded == value2)
  }

  test("EC Private Key from Nimbus JOSE Website") {
    val json =
      """
        |{
        |  "kty" : "EC",
        |  "kid" : "f0ce6d0a-e9d3-4d6d-a2b3-ee539b74cb9f",
        |  "crv" : "P-256",
        |  "x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
        |  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
        |  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
        |}
        |""".stripMargin
    val Right(value) = decode[Jwk.EllipticCurve](json)
    assert(value.privateKey.isDefined)
  }

  test("Serialized should be the same as from string") {
    val json =
      """
        |{
        |  "kty" : "EC",
        |  "kid" : "f0ce6d0a-e9d3-4d6d-a2b3-ee539b74cb9f",
        |  "crv" : "P-256",
        |  "x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
        |  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
        |  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
        |}
        |""".stripMargin
    val Right(value) = decode[Jwk.EllipticCurve](json)
    assert(value.privateKey.isDefined)
    val Right(viaJson) = value.asJson.as[Jwk.EllipticCurve]
    assert(viaJson.privateKey.isDefined)
    assert(viaJson === value)
  }

  test("HMac256 from Nimbus JOSE Website") {
    val json =
      """
        |{
        |  "kty" : "oct",
        |  "kid" : "0afee142-a0af-4410-abcc-9f2d44ff45b5",
        |  "alg" : "HS256",
        |  "k"   : "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
        |}
        |""".stripMargin

    val value = decode[Jwk.HMac](json)
    assert(value.isRight)
  }
}
