package jwk
import java.net.URI
import sttp.client3._
import io.circe.jawn
import jwk.circe._
import sttp.model.Uri
import sttp.monad.MonadError
import sttp.monad.syntax._

class SttpJwkProvider[F[_], +S] private (implicit backend: SttpBackend[F, S]) extends JwkProvider[F] {
  private implicit val monad: MonadError[F] = backend.responseMonad
  override def load(uri: URI): F[JwkSet] = {
    val req      = basicRequest.get(Uri(uri))
    val response = req.send(backend)
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
