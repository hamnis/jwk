inThisBuild(Seq(
  scalaVersion := "2.12.8",
  scalacOptions ++= Seq(
    "-Ypartial-unification",
    "-feature",
    "-language:higherKinds",
    "-language:implicitConversions",
    "-unchecked",
    "-deprecation",
  )
))

val core = project.settings(
  libraryDependencies ++= Seq(
    "io.circe"  %% "circe-core" % "0.11.1",
    "io.circe"  %% "circe-parser" % "0.11.1",
    "org.scalatest" %% "scalatest" % "3.0.8" % Test
  )
)