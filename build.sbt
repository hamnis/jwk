inThisBuild(
  Seq(
    scalaVersion := "2.13.1",
    scalacOptions ++= Seq(
      "-feature",
      "-language:higherKinds",
      "-language:implicitConversions",
      "-unchecked",
      "-deprecation"
    ),
    addCompilerPlugin("com.olegpy" %% "better-monadic-for" % "0.3.1")
  )
)

val core = project.settings(
  libraryDependencies ++= Seq(
    "org.scodec"    %% "scodec-bits"  % "1.1.12",
    "io.circe"      %% "circe-core"   % "0.13.0-RC1",
    "org.typelevel" %% "cats-effect"  % "2.0.0",
    "io.circe"      %% "circe-parser" % "0.13.0-RC1",
    "org.scalatest" %% "scalatest"    % "3.1.0" % Test
  )
)

val http4s = project
  .dependsOn(core)
  .settings(
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-client" % "0.21.0-RC1",
      "org.http4s" %% "http4s-circe"  % "0.21.0-RC1"
    )
  )

val sttp = project
  .dependsOn(core)
  .settings(
    libraryDependencies ++= Seq(
      "com.softwaremill.sttp" %% "core" % "1.7.2"
    )
  )

val jwk = project.in(file(".")).aggregate(core, http4s)
