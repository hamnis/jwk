package jwk
import java.net.URI

import com.softwaremill.sttp._
import com.softwaremill.sttp.monadSyntax._
import io.circe.jawn
import jwk.circe._

class SttpJwkProvider[F[_], -S] private (implicit backend: SttpBackend[F, S]) extends JwkProvider[F] {
  private implicit val monad: MonadError[F] = backend.responseMonad
  override def load(uri: URI): F[JwkSet] = {
    val req      = sttp.get(Uri(uri))
    val response = req.send()
    response
      .flatMap { res =>
        res.body.left
          .map(e => new IllegalArgumentException(e))
          .flatMap(
            json =>
              jawn
                .decode[JwkSet](json)
          )
          .fold(e => monad.error[JwkSet](e), ok => monad.unit(ok))
      }
  }
}

object SttpJwkProvider {
  def apply[F[_], S](implicit backend: SttpBackend[F, S]) = new SttpJwkProvider[F, S]()
}
