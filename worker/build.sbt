ThisBuild / scalaVersion := "3.3.4"
ThisBuild / organization := "nukesandbox"
ThisBuild / version := "1.0.0"

lazy val root = (project in file("."))
  .settings(
    name := "nukesandbox-worker",
    libraryDependencies ++= Seq(
      "org.apache.pekko" %% "pekko-actor-typed" % "1.1.3",
      "org.apache.pekko" %% "pekko-stream" % "1.1.3",
      "org.apache.pekko" %% "pekko-http" % "1.1.0",
      "org.apache.pekko" %% "pekko-http-spray-json" % "1.1.0",
      "org.apache.pekko" %% "pekko-connectors-kafka" % "1.1.0",
      "ch.qos.logback" % "logback-classic" % "1.5.16",
      "org.scalatest" %% "scalatest" % "3.2.19" % Test
    )
  )
